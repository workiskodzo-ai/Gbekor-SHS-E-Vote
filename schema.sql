-- Gbekor SHS e-voting: run this whole file once in Supabase > SQL Editor
create extension if not exists pgcrypto with schema extensions;

create table settings(id int primary key default 1 check (id=1), voting_open boolean not null default false, admin_hash text not null);
create table voters(student_id text primary key, name text not null, pin_hash text not null, has_voted boolean not null default false, attempts int not null default 0);
create table positions(id serial primary key, title text not null, sort int not null default 0);
create table candidates(id serial primary key, position_id int not null references positions on delete cascade, name text not null);
-- votes hold NO voter reference, so ballots stay secret. candidate_id null = abstain.
create table votes(id bigserial primary key, position_id int not null references positions on delete cascade, candidate_id int references candidates on delete cascade);

-- Lock every table: the app can only act through the functions below.
alter table settings enable row level security;
alter table voters enable row level security;
alter table positions enable row level security;
alter table candidates enable row level security;
alter table votes enable row level security;
revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;

-- CHANGE THIS ADMIN PASSWORD before going live (see README)
insert into settings(admin_hash) values (extensions.crypt('CHANGE-ME-NOW', extensions.gen_salt('bf')));

create function _auth(p_sid text, p_pin text) returns voters language plpgsql security definer set search_path=public,extensions as $$
declare v voters;
begin
  select * into v from voters where student_id = upper(trim(p_sid)) for update;
  if not found or v.attempts >= 5 then return null; end if;
  if v.pin_hash = crypt(p_pin, v.pin_hash) then
    update voters set attempts = 0 where student_id = v.student_id;
    return v;
  end if;
  update voters set attempts = attempts + 1 where student_id = v.student_id;
  return null;
end $$;

create function _admin(p_pw text) returns void language plpgsql security definer set search_path=public,extensions as $$
begin
  if not exists (select 1 from settings where admin_hash = crypt(p_pw, admin_hash)) then
    raise exception 'Wrong admin password';
  end if;
end $$;

create function get_ballot(p_student_id text, p_pin text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v voters;
begin
  v := _auth(p_student_id, p_pin);
  if v.student_id is null then return jsonb_build_object('ok',false,'error','Invalid ID or PIN. After 5 wrong tries your account locks; ask the election officer.'); end if;
  if v.has_voted then return jsonb_build_object('ok',false,'error','You have already voted.'); end if;
  if not (select voting_open from settings) then return jsonb_build_object('ok',false,'error','Voting is not open right now.'); end if;
  return jsonb_build_object('ok',true,'name',v.name,'positions',coalesce((
    select jsonb_agg(jsonb_build_object('id',p.id,'title',p.title,'candidates',coalesce((
      select jsonb_agg(jsonb_build_object('id',c.id,'name',c.name) order by c.id) from candidates c where c.position_id=p.id),'[]'::jsonb))
      order by p.sort,p.id) from positions p),'[]'::jsonb));
end $$;

create function cast_vote(p_student_id text, p_pin text, p_choices jsonb) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v voters; p record; cid int;
begin
  v := _auth(p_student_id, p_pin);   -- locks the voter row until this transaction ends
  if v.student_id is null then return jsonb_build_object('ok',false,'error','Invalid ID or PIN.'); end if;
  if v.has_voted then return jsonb_build_object('ok',false,'error','You have already voted.'); end if;
  if not (select voting_open from settings) then return jsonb_build_object('ok',false,'error','Voting is closed.'); end if;
  for p in select id from positions loop
    cid := nullif(p_choices->>(p.id::text), '')::int;
    if cid is not null and not exists (select 1 from candidates where id=cid and position_id=p.id) then
      raise exception 'Invalid choice';
    end if;
    insert into votes(position_id, candidate_id) values (p.id, cid);
  end loop;
  update voters set has_voted = true where student_id = v.student_id;
  return jsonb_build_object('ok',true);
end $$;

create function admin_state(p_pw text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
begin
  perform _admin(p_pw);
  return jsonb_build_object(
    'voting_open',(select voting_open from settings),
    'total',(select count(*) from voters),
    'voted',(select count(*) from voters where has_voted),
    'positions',coalesce((select jsonb_agg(jsonb_build_object('id',p.id,'title',p.title,
      'abstain',(select count(*) from votes where position_id=p.id and candidate_id is null),
      'candidates',coalesce((select jsonb_agg(jsonb_build_object('id',c.id,'name',c.name,
        'votes',(select count(*) from votes where candidate_id=c.id)) order by c.id) from candidates c where c.position_id=p.id),'[]'::jsonb))
      order by p.sort,p.id) from positions p),'[]'::jsonb));
end $$;

create function admin_set_open(p_pw text, p_open boolean) returns void language plpgsql security definer set search_path=public,extensions as $$
begin perform _admin(p_pw); update settings set voting_open = p_open; end $$;

create function admin_add_position(p_pw text, p_title text) returns void language plpgsql security definer set search_path=public,extensions as $$
begin perform _admin(p_pw); insert into positions(title, sort) values (trim(p_title), (select coalesce(max(sort),0)+1 from positions)); end $$;

create function admin_add_candidate(p_pw text, p_position_id int, p_name text) returns void language plpgsql security definer set search_path=public,extensions as $$
begin perform _admin(p_pw); insert into candidates(position_id, name) values (p_position_id, trim(p_name)); end $$;

-- Adds voters, or resets the PIN and unlocks an existing one (never resets has_voted)
create function admin_add_voters(p_pw text, p_voters jsonb) returns void language plpgsql security definer set search_path=public,extensions as $$
begin
  perform _admin(p_pw);
  insert into voters(student_id, name, pin_hash)
    select upper(trim(x->>'student_id')), trim(x->>'name'), crypt(x->>'pin', gen_salt('bf')) from jsonb_array_elements(p_voters) x
  on conflict (student_id) do update set name = excluded.name, pin_hash = excluded.pin_hash, attempts = 0;
end $$;

revoke all on all functions in schema public from public, anon, authenticated;
grant execute on function get_ballot(text,text), cast_vote(text,text,jsonb), admin_state(text),
  admin_set_open(text,boolean), admin_add_position(text,text), admin_add_candidate(text,int,text), admin_add_voters(text,jsonb) to anon;
