
## Creating a release

### Determine version number

Ensure you're on master and up to date with the remote, then git desccribe should returns the latest tag:

```bash
$ git checkout master 
$ git pull origin master
$ git describe
v0.15.1
```

Here our current version is `v0.15.1`, and we want to create the `v0.15.2` release. We'll use this number in the rest of the document.

### Update version

Before tagging the new version, the [version/version.go#L25-L26](./version/version.go#L25-L26) file must be updated with the new version number.

```diff
-	TMCoreSemVer     = "0.15.1"
+	TMCoreSemVer     = "0.15.2"
	TMBaselineSemVer = "0.33.6"
```

Commit this change, tag the new version and push it to the remote. Depending on your priviledges, you may need to commit this change to a branch and open a pull request instead of commiting directly to master. 

```bash
git add ./version/version.go && git commit -m "chore: bump TMCoreSemVer to v0.15.2"
```

Once the version change reached master, you can now create the tag:

```bash
git tag -a v0.15.2 -m v0.15.2

git push origin v0.15.2
```


### Create release on github

Now head to [the release page](https://github.com/fetchai/cosmos-consensus/releases) and you must see the tag you just pushed there.

Edit it and:

- set the release title to the version number (here `v0.15.2`)
- Update the description from the following template

```markdown
## Changes in this release

* Main change 1
* Main change 2
* ...

## Ecosystem

| Component  | Baseline |
| ---------- | -------- |
| Tendermint | 0.33.6   |

## Pull Requests

* relevant PR 1
* relevant PR 2
* ...
```

- Tick the `This is a pre-release` box (until mainnet release)
- Hit `Publish release`


## Next steps

To use this new release, both `cosmos-sdk` and `fetchd` need to be updated.

### Update cosmos-sdk

First, update [cosmos-sdk](https://github.com/fetchai/cosmos-sdk) `go.mod` file to reference our new version:

```diff
- replace github.com/tendermint/tendermint => github.com/fetchai/cosmos-consensus v0.15.1
+ replace github.com/tendermint/tendermint => github.com/fetchai/cosmos-consensus v0.15.2
```

then run `go mod tidy` to update the sum file, and publish a new `cosmos-sdk` release following the release guide in this repository.

### Update fetchd

Once `cosmos-sdk` release is published, [fetchd](https://github.com/fetchai/fetchd) `go.mod` file can be updated to change both `cosmos-sdk` and `cosmos-consensus` versions:

```diff
- replace github.com/cosmos/cosmos-sdk => github.com/fetchai/cosmos-sdk v0.15.0
+ replace github.com/cosmos/cosmos-sdk => github.com/fetchai/cosmos-sdk v0.15.1

- replace github.com/tendermint/tendermint => github.com/fetchai/cosmos-consensus v0.15.1
+ replace github.com/tendermint/tendermint => github.com/fetchai/cosmos-consensus v0.15.2
```

then run `go mod tidy` to update the sum file.
