from sqlalchemy import create_engine

engine = create_engine("postgresql://admin:__HG_FAKE_DB_PASSWORD__@prod-db.internal:5432/orders")
