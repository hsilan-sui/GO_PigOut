CREATE TABLE "Customer" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "name" varchar(255),
  "email" varchar(255) UNIQUE,
  "phone" varchar(20),
  "password" varchar(255),
  "role" varchar(50),
  "created_at" timestamp
);

CREATE TABLE "DeliveryPerson" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "name" varchar(255),
  "phone" varchar(20),
  "password" varchar(255),
  "role" varchar(50),
  "created_at" timestamp
);

CREATE TABLE "Vendor" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "name" varchar(255),
  "address_id" int,
  "phone" varchar(20),
  "password" varchar(255),
  "role" varchar(50),
  "created_at" timestamp
);

CREATE TABLE "MenuItem" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "vendor_id" int,
  "name" varchar(255),
  "price" decimal(10,2),
  "description" text,
  "available" boolean,
  "created_at" timestamp
);

CREATE TABLE "Cart" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "customer_id" int,
  "created_at" timestamp
);

CREATE TABLE "CartItem" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "cart_id" int,
  "menu_item_id" int,
  "quantity" int,
  "created_at" timestamp
);

CREATE TABLE "Order" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "customer_id" int,
  "delivery_person_id" int,
  "vendor_id" int,
  "total_price" decimal(10,2),
  "status" varchar(50),
  "order_time" timestamp,
  "delivery_time" timestamp,
  "created_at" timestamp
);

CREATE TABLE "OrderItem" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "order_id" int,
  "menu_item_id" int,
  "quantity" int,
  "price" decimal(10,2)
);

CREATE TABLE "Payment" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "order_id" int,
  "payment_method" varchar(50),
  "payment_status" varchar(50),
  "total_price" decimal(10,2),
  "created_at" timestamp
);

CREATE TABLE "Address" (
  "id" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "street" varchar(255),
  "city" varchar(100),
  "postal_code" varchar(10),
  "created_at" timestamp
);

-- 添加外鍵約束
ALTER TABLE "Vendor" ADD FOREIGN KEY ("address_id") REFERENCES "Address" ("id");

ALTER TABLE "MenuItem" ADD FOREIGN KEY ("vendor_id") REFERENCES "Vendor" ("id");

ALTER TABLE "Cart" ADD FOREIGN KEY ("customer_id") REFERENCES "Customer" ("id");

ALTER TABLE "CartItem" ADD FOREIGN KEY ("cart_id") REFERENCES "Cart" ("id");

ALTER TABLE "CartItem" ADD FOREIGN KEY ("menu_item_id") REFERENCES "MenuItem" ("id");

ALTER TABLE "Order" ADD FOREIGN KEY ("customer_id") REFERENCES "Customer" ("id");

ALTER TABLE "Order" ADD FOREIGN KEY ("delivery_person_id") REFERENCES "DeliveryPerson" ("id");

ALTER TABLE "Order" ADD FOREIGN KEY ("vendor_id") REFERENCES "Vendor" ("id");

ALTER TABLE "OrderItem" ADD FOREIGN KEY ("order_id") REFERENCES "Order" ("id");

ALTER TABLE "OrderItem" ADD FOREIGN KEY ("menu_item_id") REFERENCES "MenuItem" ("id");

ALTER TABLE "Payment" ADD FOREIGN KEY ("order_id") REFERENCES "Order" ("id");
