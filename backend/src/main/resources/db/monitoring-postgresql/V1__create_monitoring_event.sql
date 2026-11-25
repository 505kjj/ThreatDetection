create table monitoring_event (
    id bigint generated always as identity primary key,
    client_id varchar(64) not null,
    event_id uuid not null,
    received_at timestamp(6) with time zone not null,
    detected_at timestamp(3) with time zone not null,
    synthetic boolean not null,
    signal varchar(32) not null,
    action varchar(8) not null,
    constraint monitoring_client_event_unique unique (client_id, event_id)
);

create index monitoring_scope_received on monitoring_event (synthetic, received_at, id);
create index monitoring_expiry on monitoring_event (received_at);
