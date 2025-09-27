-- Active: 1757826919474@@127.0.0.1@3306@db_network_scanning_system
-- Membuat DB

CREATE DATABASE IF NOT EXISTS db_network_scanning_system; -- membuat db

USE db_network_scanning_system; --memgggunakan db

-- CREATE TABLE IF NOT EXISTS network_scans(
--     network_id CHAR(5) NOT NULL AUTO_INCREMENT PRIMARY KEY,
--     network_target VARCHAR(255) NOT NULL,
--     scan_date DATETIME NOT NULL
-- )ENGINE=InnoDB; -- membuat tabel network_scans

-- CREATE TABLE IF NOT EXISTS network_scan_results(
--     result_network_id CHAR(5) NOT NULL AUTO_INCREMENT PRIMARY KEY,
--     network_id IN CHAR(5) NOT NULL,
--     ip_address VARCHAR(255) NOT NULL,
--     scan_date DATETIME NOT NULL,
--     FOREIGN KEY (network_id) REFERENCES network_scans(network_id)
-- )ENGINE=InnoDB; --membuat tabel network_scan_results

CREATE TABLE IF NOT EXISTS port_scan(
    port_scan_id CHAR(5) NOT NULL PRIMARY KEY,
    target_ip VARCHAR(255),
    scan_date DATETIME,
    total_port INT NOT NULL,
    open_port INT NOT NULL
)ENGINE=InnoDB; --membuat table port_scan yang

CREATE TABLE IF NOT EXISTS port_scan_result(
    port_scan_result_id CHAR(5) NOT NULL PRIMARY KEY,
    port_scan_id CHAR(5) NOT NULL,
    port_number INT NOT NULL,
    port_status ENUM('open','closed','filtered') NOT NULL,
    services_name VARCHAR(255),
    FOREIGN KEY (port_scan_id) REFERENCES port_scan(port_scan_id) 
)ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS vulnerabilities(
    vuln_id CHAR(5) NOT NULL PRIMARY KEY,
    port_scan_result_id CHAR(5) NOT NULL,
    vulnerability_name VARCHAR(255) NOT NULL,
    descriptions TEXT NOT NULL,
    severity ENUM('low','medium','high','critical'),
    FOREIGN KEY (port_scan_result_id) REFERENCES port_scan_result(port_scan_result_id)
)ENGINE=InnoDB;

-- INSERT INTO port_scan VALUES ("A001","192.168.1.1","2007-08-10 11:30:00","1000","3")

