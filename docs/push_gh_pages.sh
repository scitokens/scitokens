#!/usr/bin/env bash
# Push Sphinx docs to GH pages

set -ex

# Setup deploy key
if [ "$1" != "dry" -a "${TRAVIS_PULL_REQUEST}" = "false"  ]; then
    openssl aes-256-cbc -K $encrypted_800a4fb7265c_key -iv $encrypted_800a4fb7265c_iv -in deploy-key.enc -out deploy-key -d
    chmod 600 deploy-key
    eval `ssh-agent -s`
    ssh-add deploy-key
fi

# Clone the gh-pages branch
git clone -b gh-pages "git@github.com:scitokens/scitokens.git" gh-pages
pushd gh-pages

# Update git configuration so I can push.
if [ "$1" != "dry" ]; then
    # Update git config.
    git config user.name "Travis Builder"
    git config user.email "team@scitokens.org"
fi

# Copy in the HTML.  You may want to change this with your documentation path.
cp -R ../build/html/* ./

# Add and commit changes.
git add -A .
git commit -m "[ci skip] Autodoc commit for $TRAVIS_COMMIT."
if [ "$1" != "dry" ]; then
    if [ "${TRAVIS_PULL_REQUEST}" = "false" ]; then
        git push -q origin gh-pages
    fi
fi

popd

