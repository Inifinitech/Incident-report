"""approves everything

Revision ID: 3482e6898aed
Revises: 
Create Date: 2024-11-08 14:00:52.884103

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3482e6898aed'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('notifications',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('message', sa.String(), nullable=False),
    sa.Column('read', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(), nullable=False),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('password', sa.String(), nullable=False),
    sa.Column('role', sa.Enum('admin', 'user'), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('incident_reports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=False),
    sa.Column('status', sa.Enum('under investigation', 'resolved', 'rejected'), nullable=True),
    sa.Column('latitude', sa.Float(), nullable=False),
    sa.Column('longitude', sa.Float(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('admins_acts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('incident_report_id', sa.Integer(), nullable=True),
    sa.Column('action', sa.Enum('status_change', 'flagged', 'resolved'), nullable=True),
    sa.Column('admin_id', sa.Integer(), nullable=True),
    sa.Column('create_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['admin_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['incident_report_id'], ['incident_reports.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('incident_medias',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('incident_report_id', sa.Integer(), nullable=False),
    sa.Column('media_type', sa.Enum('image', 'video'), nullable=False),
    sa.Column('media_url', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['incident_report_id'], ['incident_reports.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('incident_medias')
    op.drop_table('admins_acts')
    op.drop_table('incident_reports')
    op.drop_table('users')
    op.drop_table('notifications')
    # ### end Alembic commands ###