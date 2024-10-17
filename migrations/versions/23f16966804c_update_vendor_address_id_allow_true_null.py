"""update Vendor address_id allow True null

Revision ID: 23f16966804c
Revises: 972d5cd703c4
Create Date: 2024-10-08 21:55:23.951669

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '23f16966804c'
down_revision = '972d5cd703c4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('Vendor', schema=None) as batch_op:
        batch_op.alter_column('address_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('Vendor', schema=None) as batch_op:
        batch_op.alter_column('address_id',
               existing_type=sa.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###