# Gbekor SHS E-Vote (PWA)

1. **Supabase**: create a free project, open SQL Editor, paste and run `schema.sql`.
2. **Change the admin password** (SQL Editor):
   `update settings set admin_hash = extensions.crypt('YourLongPassword', extensions.gen_salt('bf'));`
3. In `index.html`, set `SB_URL` and `SB_KEY` (Project Settings > API: Project URL and the `anon` public key).
4. **GitHub**: create a repo, upload all files here, then Settings > Pages > Deploy from branch `main` / root.
5. On Android, open the Pages link in Chrome > menu > **Install app**.
6. Open `<your link>/#admin`: add positions, candidates, voters (print the PINs), then **Open voting**.

Voting is one-per-student, enforced in the database. Test with dummy voters, then clear test data
(`truncate votes, voters, candidates, positions restart identity cascade;`) before the real election.
