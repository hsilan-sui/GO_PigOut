"""Add category field to MenuItem

Revision ID: 69a143dd2bf4
Revises: 1a3974d25477
Create Date: 2024-10-27 16:23:24.178282

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '69a143dd2bf4'
down_revision = '1a3974d25477'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('MenuItem', schema=None) as batch_op:
        batch_op.add_column(sa.Column('category', sa.String(length=50), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('MenuItem', schema=None) as batch_op:
        batch_op.drop_column('category')

    # ### end Alembic commands ###
