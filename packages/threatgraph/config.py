"""Typed configuration loading and hashing."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

# Editable installs resolve the repo from this file; installed copies (e.g. Docker) set TG_REPO_ROOT.
REPO_ROOT = Path(os.environ.get("TG_REPO_ROOT") or Path(__file__).resolve().parents[2])
CONFIG_DIR = REPO_ROOT / "configs"
DAY_SECONDS = 86_400

DatasetMode = Literal["synthetic", "lanl"]


class TimeWindow(BaseModel):
    start_seconds: int = 0
    end_seconds: int | None = None  # inclusive; None = until end of file

    def contains(self, t: int) -> bool:
        return t >= self.start_seconds and (self.end_seconds is None or t <= self.end_seconds)


class IngestConfig(BaseModel):
    block_size_bytes: int = Field(default=16 * 1024 * 1024, ge=64 * 1024)
    assume_sorted: bool = True
    hash_source_files: bool = False


class RedteamConfig(BaseModel):
    # Which auth principal the red-team `user@domain` column is matched against.
    user_field: Literal["source", "destination"] = "source"


class FeatureConfig(BaseModel):
    window_seconds: int = Field(default=3600, gt=0)
    burst_seconds: int = Field(default=300, gt=0)
    baseline_windows: int = Field(default=24, gt=1)
    principals: Literal["users_only", "all"] = "users_only"
    # Events are processed in time chunks of this size with carried state, so peak memory
    # follows one chunk rather than the whole time window. Output does not depend on it.
    chunk_seconds: int = Field(default=86_400, gt=0)
    # A source computer counts as a pivot if the principal reached it as a remote
    # destination within this many seconds before (graph feature `n_pivot_src`).
    pivot_lookback_seconds: int = Field(default=86_400, gt=0)

    @model_validator(mode="after")
    def _check(self) -> FeatureConfig:
        if self.window_seconds % self.burst_seconds:
            raise ValueError("window_seconds must be a multiple of burst_seconds")
        if self.chunk_seconds % self.window_seconds:
            raise ValueError("chunk_seconds must be a multiple of window_seconds")
        return self


class GraphConfig(BaseModel):
    # Two-hop expansion skips computers used by more than this many principals in the
    # requested range (domain controllers, file servers): they connect everyone to everyone.
    hub_max_principals: int = Field(default=15, ge=1)
    sample_events_per_edge: int = Field(default=3, ge=1, le=10)
    export_max_edges: int = Field(default=60, ge=1, le=300)


class SplitConfig(BaseModel):
    warmup_end_day: float
    train_end_day: float
    validation_end_day: float
    test_end_day: float

    @model_validator(mode="after")
    def _ordered(self) -> SplitConfig:
        days = [self.warmup_end_day, self.train_end_day, self.validation_end_day, self.test_end_day]
        if days != sorted(days) or len(set(days)) != len(days):
            raise ValueError(f"split boundaries must be strictly increasing, got {days}")
        return self

    def boundaries_seconds(self) -> dict[str, tuple[int, int]]:
        """Half-open [start, end) second ranges per split, keyed by split name."""
        b = [0, self.warmup_end_day, self.train_end_day, self.validation_end_day, self.test_end_day]
        s = [round(x * DAY_SECONDS) for x in b]
        names = ["warmup", "train", "validation", "test"]
        return {n: (s[i], s[i + 1]) for i, n in enumerate(names)}


class DatasetConfig(BaseModel):
    name: str
    mode: DatasetMode
    description: str
    raw_dir: str
    files: dict[str, str]
    processed_dir: str
    artifacts_dir: str
    time_window: TimeWindow = TimeWindow()
    ingest: IngestConfig = IngestConfig()
    redteam: RedteamConfig = RedteamConfig()
    features: FeatureConfig = FeatureConfig()
    graph: GraphConfig = GraphConfig()
    splits: SplitConfig
    seed: int = 42

    @model_validator(mode="after")
    def _aligned(self) -> DatasetConfig:
        for name, (start, end) in self.splits.boundaries_seconds().items():
            if start % self.features.window_seconds or end % self.features.window_seconds:
                raise ValueError(f"split '{name}' boundary is not aligned to window_seconds")
        return self

    @staticmethod
    def _resolve(p: str) -> Path:
        path = Path(p)
        return path if path.is_absolute() else REPO_ROOT / path

    @property
    def raw_path(self) -> Path:
        return self._resolve(self.raw_dir)

    @property
    def processed_path(self) -> Path:
        return self._resolve(self.processed_dir)

    @property
    def artifacts_path(self) -> Path:
        return self._resolve(self.artifacts_dir)

    def raw_file(self, kind: str) -> Path:
        return self.raw_path / self.files[kind]


class ModelSpec(BaseModel):
    kind: Literal["robust_z", "isolation_forest"]
    display_name: str
    description: str | None = None
    # A list of feature names, "all", or the name of a group in `feature_groups`.
    features: list[str] | str
    params: dict[str, Any] = {}


class AblationSpec(BaseModel):
    """A pair of models that differ only in their inputs, compared on every split."""

    title: str
    baseline: str
    candidate: str
    note: str


class ThresholdPolicy(BaseModel):
    type: Literal["validation_alert_rate"] = "validation_alert_rate"
    alert_rate: float = Field(default=0.01, gt=0, lt=1)


class ModelsConfig(BaseModel):
    feature_set: str
    feature_groups: dict[str, list[str]]
    threshold_policy: ThresholdPolicy
    models: dict[str, ModelSpec]
    ablations: dict[str, AblationSpec] = {}

    @property
    def features(self) -> list[str]:
        return [f for group in self.feature_groups.values() for f in group]

    def features_for(self, model_id: str) -> list[str]:
        spec = self.models[model_id]
        if isinstance(spec.features, list):
            return list(spec.features)
        if spec.features == "all":
            return self.features
        return list(self.feature_groups[spec.features])

    @model_validator(mode="after")
    def _check(self) -> ModelsConfig:
        for m, spec in self.models.items():
            if isinstance(spec.features, str) and spec.features not in (
                "all",
                *self.feature_groups,
            ):
                raise ValueError(f"model {m}: unknown feature group '{spec.features}'")
        for a, ab in self.ablations.items():
            for m in (ab.baseline, ab.candidate):
                if m not in self.models:
                    raise ValueError(f"ablation {a}: unknown model '{m}'")
        return self


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        return yaml.safe_load(fh)


def load_dataset_config(name: str, path: Path | None = None) -> DatasetConfig:
    raw = _read_yaml(path or CONFIG_DIR / "datasets.yaml")["datasets"]
    if name not in raw:
        raise KeyError(f"unknown dataset '{name}'; known: {sorted(raw)}")
    return DatasetConfig(name=name, **raw[name])


def load_models_config(path: Path | None = None) -> ModelsConfig:
    return ModelsConfig(**_read_yaml(path or CONFIG_DIR / "models.yaml"))


def config_hash(*objs: BaseModel | dict[str, Any]) -> str:
    """Stable short hash of one or more configs (key order independent)."""
    payload = [o.model_dump(mode="json") if isinstance(o, BaseModel) else o for o in objs]
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()[:16]
