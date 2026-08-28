"""Add optional JWT token to scans.

Revision ID: 20260828_02
Revises: 20260828_01
Create Date: 2026-08-28 00:01:00
"""

import sqlalchemy as sa
from alembic import op


revision = "20260828_02"
down_revision = "20260828_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("jwt_token", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "jwt_token")
