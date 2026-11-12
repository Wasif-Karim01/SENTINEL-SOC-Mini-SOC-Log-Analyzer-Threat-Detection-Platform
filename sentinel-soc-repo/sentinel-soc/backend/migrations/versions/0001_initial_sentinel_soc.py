"""Initial SENTINEL SOC normalized schema migration."""
revision = "0001_initial_sentinel_soc"
down_revision = None

def upgrade():
    from app.core.database import init_db
    init_db()

def downgrade():
    pass
