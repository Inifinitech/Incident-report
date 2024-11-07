"""Add password hashing to User model

Revision ID: 785946241bc9
Revises: a07e5f9b00e4
Create Date: 2024-11-07 16:40:32.991026

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '785946241bc9'
down_revision = 'a07e5f9b00e4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('notifications', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('user_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('notifications', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.INTEGER(), nullable=False))
        batch_op.create_foreign_key(None, 'users', ['user_id'], ['id'])

    # ### end Alembic commands ###
