"""Deployment of a verified artifact.

The package holds the pieces that turn a signed artifact into a running
microservice:

* ``service`` - the deployment, the weighted router and the canary rollout.
* ``service_app`` - the HTTP wrapper that is copied into the image.
"""

from __future__ import annotations

from oracle_hcm.deploy.service import (
    DeploymentConfig,
    DeploymentError,
    DeploymentRequest,
    DeploymentService,
    SlotState,
)

__all__ = [
    "DeploymentConfig",
    "DeploymentError",
    "DeploymentRequest",
    "DeploymentService",
    "SlotState",
]
