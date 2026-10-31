#!/usr/bin/env bash
# Build the mdBook in docs/ and publish it to the gh-pages branch, which GitHub Pages serves at
# https://agustinustheodorus.com/canggu-blockchain/ (the owner's user site has a custom domain).
#
#   scripts/publish-docs.sh            build, add sitemap.xml, commit to gh-pages and push
#   scripts/publish-docs.sh --dry-run  build and add sitemap.xml only
set -euo pipefail

SITE="https://agustinustheodorus.com/canggu-blockchain"
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

mdbook build docs

# A sitemap with absolute URLs helps search engines find every chapter.
python3 - "$SITE" docs/book <<'EOF'
import os, sys, datetime
site, out = sys.argv[1], sys.argv[2]
today = datetime.date.today().isoformat()
urls = []
for root, _, files in os.walk(out):
	for f in sorted(files):
		if f.endswith('.html') and f not in ('404.html', 'print.html', 'toc.html'):
			rel = os.path.relpath(os.path.join(root, f), out).replace(os.sep, '/')
			urls.append(site + '/' + ('' if rel == 'index.html' else rel))
entries = ''.join(f'  <url><loc>{u}</loc><lastmod>{today}</lastmod></url>\n' for u in sorted(urls))
open(os.path.join(out, 'sitemap.xml'), 'w').write(
	'<?xml version="1.0" encoding="UTF-8"?>\n'
	'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + entries + '</urlset>\n')
print(f'sitemap.xml: {len(urls)} pages')
EOF
# Serve the files as they are (no Jekyll processing).
touch docs/book/.nojekyll

if [ "${1:-}" = "--dry-run" ]; then
	echo "dry run: built docs/book"
	exit 0
fi

SOURCE=$(git rev-parse --short HEAD)
WORK=$(mktemp -d)
trap 'git worktree remove --force "$WORK" 2>/dev/null || true' EXIT
if git ls-remote --exit-code --heads origin gh-pages >/dev/null 2>&1; then
	git fetch -q origin gh-pages
	git worktree add -q --detach "$WORK" origin/gh-pages
else
	git worktree add -q --detach "$WORK"
	git -C "$WORK" checkout -q --orphan gh-pages
fi
git -C "$WORK" rm -rq --ignore-unmatch . >/dev/null
cp -R docs/book/. "$WORK/"
git -C "$WORK" add -A
if git -C "$WORK" diff --cached --quiet; then
	echo "nothing to publish"
	exit 0
fi
git -C "$WORK" commit -q -m "Publish docs from $SOURCE"
git -C "$WORK" push -q origin HEAD:gh-pages
echo "published $SOURCE to gh-pages: $SITE/"
