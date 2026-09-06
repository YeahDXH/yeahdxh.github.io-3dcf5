Add a small, short-named puzzle intro page at /puzzle/intro.html.

Why: the long filename you used earlier sometimes caused 404s when browsers followed the redirect. To avoid file-name length/encoding issues we add a short canonical path that the API already falls back to by default.

What I added
- puzzle/intro.html — the same "a quick note" puzzle content as the long file.

Next steps for you
1) Redeploy on Vercel (push will trigger a deploy automatically). Wait for the deployment to finish.
2) Test the literal pass (case-insensitive):
   curl -i -X POST "https://<your-site>/api/check-pass" -H "Content-Type: application/x-www-form-urlencoded" -d "pass=start%20the%20puzzle" | sed -n '1,12p'
   Or fill the form on /reality.html and submit.
3) If everything works, you can remove the extremely long filename file from the repo later if you want.

If you want, I can also:
- Update the API handler to prefer SECRET_PAGE if set, and fall back to /puzzle/intro.html only if SECRET_PAGE is missing (I left the current behavior that already does this). 
- Remove the old long file to keep the repo tidy.
