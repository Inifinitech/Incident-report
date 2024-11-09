"""removed title

Revision ID: d6b1597cac04
Revises: 3482e6898aed
Create Date: 2024-11-08 14:30:22.930167

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd6b1597cac04'
down_revision = '3482e6898aed'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('incident_reports', schema=None) as batch_op:
        batch_op.drop_column('title')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('incident_reports', schema=None) as batch_op:
        batch_op.add_column(sa.Column('title', sa.VARCHAR(), nullable=False))

    # ### end Alembic commands ###