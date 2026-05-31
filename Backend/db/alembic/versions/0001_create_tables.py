"""create initial tables

Revision ID: 0001_create_tables
Revises: 
Create Date: 2026-05-26 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_create_tables'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "predictions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("protocol_type", sa.String(length=32), nullable=True),
        sa.Column("service", sa.String(length=64), nullable=True),
        sa.Column("predicted_label", sa.String(length=32), nullable=True),
        sa.Column("normal_probability", sa.Float(), nullable=True),
        sa.Column("attack_probability", sa.Float(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("validation_warnings", sa.Integer(), nullable=True),
        sa.Column("validation_errors", sa.Integer(), nullable=True),
        sa.Column("packet_summary", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_predictions_id"), "predictions", ["id"], unique=False)
    op.create_index(op.f("ix_predictions_timestamp"), "predictions", ["timestamp"], unique=False)

    op.create_table(
        "traffic_stats",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
        sa.Column("total_predictions", sa.Integer(), nullable=True),
        sa.Column("attacks_detected", sa.Integer(), nullable=True),
        sa.Column("normal_traffic", sa.Integer(), nullable=True),
        sa.Column("uncertain", sa.Integer(), nullable=True),
        sa.Column("uptime_seconds", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_traffic_stats_id"), "traffic_stats", ["id"], unique=False)
    op.create_index(op.f("ix_traffic_stats_timestamp"), "traffic_stats", ["timestamp"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_traffic_stats_timestamp"), table_name="traffic_stats")
    op.drop_index(op.f("ix_traffic_stats_id"), table_name="traffic_stats")
    op.drop_table("traffic_stats")

    op.drop_index(op.f("ix_predictions_timestamp"), table_name="predictions")
    op.drop_index(op.f("ix_predictions_id"), table_name="predictions")
    op.drop_table("predictions")
