# SURF Data Repository download tool

Automated download tool for user basket or favourites.

### Requirements
- Python 3
- Packages (see 'Install')

### Install
Download the latest release and make sure all required Python packages are installed:

```sh
pip install -r requirements.txt
```

### General usage

```sh
./repository-download.py [options] [--favourites] [--target <url>] <token>
```

where `token` is your token generated in the user interface of the Data Repository and the value for `--target` must be a fully qualified domain name including a protocol (e.g. `https://repository.surfsara.nl`).

Note: the token used is unique for the instance of the repository used and therefore cannot be used for other instances.

By default, the download tool will download the items in your download basket, but with the `--favourites` option you can download the items in your favourites listing.
