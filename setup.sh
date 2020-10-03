#! /bin/sh

### Script to setup project ###
### To be run only after clone ###

function display_usage {
    echo "Usage: $0 <development|production>"
    exit 1
}

function check_pipenv {
    ### Setup pipenv ###
    # check if pipenv installed, otherwise install it
    pipenv --version &>/dev/null; exit_code=$?
    if [$exit_code -ne 0]; then
        pip install pipenv
    fi
}

ENVIRONMENT=$1
if ! [[ "$ENVIRONMENT" =~ ^(development|production)$ ]]; then
    display_usage
fi


if [[ "$ENVIRONMENT" = "development" ]]; then
    echo "Setting up your development environment..."

    ### Setup git hooks ###
    # Remove all git hooks from .git/hooks directory for this project
    find .git/hooks -type l -exec rm {} \;

    # Add a symlink in .git/hooks directory from .githooks directory in current project
    # Thus all hooks should be named as in .git/hooks directory 
    find .githooks -type f -exec ln -sf ../../{} .git/hooks/ \;

    check_pipenv

    ### Setup direnv ###
    # check if direnv installed, otherwise install it
    direnv --version &>/dev/null; exit_code=$?
    if [$exit_code -ne 0]; then
        echo "Please install direnv and run this script again"
        exit 1
    else
        # allow direnv access to .envrc file
        direnv allow .
    fi


    ### Install dependencies ###
    # start virtual env
    pipenv shell
    
    # install dependencies
    pipenv install --dev
else 
    echo "Setting up your production environment..."

    check_pipenv

    # start virtual environment
    pipenv shell

    # install production dependencies
    pipenv install --ignore-pipfile
fi
