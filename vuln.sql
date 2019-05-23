drop table if exists users;
drop table if exists vendors;
drop table if exists devices;
drop table if exists inventory;
drop table if exists refs;
drop table if exists vuln;

create table users (
    userid integer PRIMARY key,
    username text not NULl,
    password text not NULL
);

create table vendors (
    vendorid integer PRIMARY key,
    name text not NULL
);

create table devices (
    deviceid integer PRIMARY key,
    product text not null,
    vendorid integer not null,
    FOREIGN key (vendorid) REFERENCES vendors (vendorid)
);

create table inventory (
    invid integer primary key,
    userid integer not null,
    deviceid integer not null,
    FOREIGN key (userid) REFERENCES users (userid),
    FOREIGN key (deviceid) references devices (deviceid)
);

create table refs (
    refid integer primary key,
    vulnid integer not NULL,
    url text,
    FOREIGN key (vulnid) references vuln (vulnid)
);

create table vuln (
    vulnid integer primary key,
    cveid text not null,
    cvss float not null,
    deviceid integer not null,
    refid integer not null,
    FOREIGN key (deviceid) references devices(deviceid)
    FOREIGN key (refid) references refs(refid)
);