CREATE TABLE `Customer` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `name` varchar(255),
  `email` varchar(255) UNIQUE,
  `phone` varchar(20),
  `password` varchar(255),
  `role` varchar(50),
  `created_at` datetime
);

CREATE TABLE `DeliveryPerson` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `name` varchar(255),
  `phone` varchar(20),
  `password` varchar(255),
  `role` varchar(50),
  `created_at` datetime
);

CREATE TABLE `Vendor` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `name` varchar(255),
  `address_id` int,
  `phone` varchar(20),
  `password` varchar(255),
  `role` varchar(50),
  `created_at` datetime
);

CREATE TABLE `MenuItem` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `vendor_id` int,
  `name` varchar(255),
  `price` decimal(10,2),
  `description` text,
  `available` boolean,
  `created_at` datetime
);

CREATE TABLE `Cart` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `customer_id` int,
  `created_at` datetime
);

CREATE TABLE `CartItem` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `cart_id` int,
  `menu_item_id` int,
  `quantity` int,
  `created_at` datetime
);

CREATE TABLE `Order` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `customer_id` int,
  `delivery_person_id` int,
  `vendor_id` int,
  `total_price` decimal(10,2),
  `status` varchar(50),
  `order_time` datetime,
  `delivery_time` datetime,
  `created_at` datetime
);

CREATE TABLE `OrderItem` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `order_id` int,
  `menu_item_id` int,
  `quantity` int,
  `price` decimal(10,2)
);

CREATE TABLE `Payment` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `order_id` int,
  `payment_method` varchar(50),
  `payment_status` varchar(50),
  `total_price` decimal(10,2),
  `created_at` datetime
);

CREATE TABLE `Address` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `street` varchar(255),
  `city` varchar(100),
  `postal_code` varchar(10),
  `created_at` datetime
);

ALTER TABLE `Vendor` ADD FOREIGN KEY (`address_id`) REFERENCES `Address` (`id`);

ALTER TABLE `MenuItem` ADD FOREIGN KEY (`vendor_id`) REFERENCES `Vendor` (`id`);

ALTER TABLE `Cart` ADD FOREIGN KEY (`customer_id`) REFERENCES `Customer` (`id`);

ALTER TABLE `CartItem` ADD FOREIGN KEY (`cart_id`) REFERENCES `Cart` (`id`);

ALTER TABLE `CartItem` ADD FOREIGN KEY (`menu_item_id`) REFERENCES `MenuItem` (`id`);

ALTER TABLE `Order` ADD FOREIGN KEY (`customer_id`) REFERENCES `Customer` (`id`);

ALTER TABLE `Order` ADD FOREIGN KEY (`delivery_person_id`) REFERENCES `DeliveryPerson` (`id`);

ALTER TABLE `Order` ADD FOREIGN KEY (`vendor_id`) REFERENCES `Vendor` (`id`);

ALTER TABLE `OrderItem` ADD FOREIGN KEY (`order_id`) REFERENCES `Order` (`id`);

ALTER TABLE `OrderItem` ADD FOREIGN KEY (`menu_item_id`) REFERENCES `MenuItem` (`id`);

ALTER TABLE `Payment` ADD FOREIGN KEY (`order_id`) REFERENCES `Order` (`id`);
