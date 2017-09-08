#!/usr/bin/env bash
# Push Sphinx docs to GH pages

set -ex
make html

# Clone the gh-pages branch
git clone -b gh-pages "https://$GH_TOKEN@github.com/scitokens/scitokens.git" gh-pages
pushd gh-pages

# Update git configuration so I can push.
if [ "$1" != "dry" ]; then
    # Update git config.
    git config user.name "Travis Builder"
    git config user.email "$EMAIL"
fi

# Copy in the HTML.  You may want to change this with your documentation path.
cp -R ../build/html/* ./

# Add and commit changes.
git add -A .
git commit -m "[ci skip] Autodoc commit for $COMMIT."
if [ "$1" != "dry" ]; then
    # -q is very important, otherwise you leak your GH_TOKEN
    git push -q origin gh-pages
fi

popd

