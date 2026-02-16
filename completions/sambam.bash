#!/usr/bin/env bash

_sambam_complete()
{
    local cur prev cword
    cword=$COMP_CWORD
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local global_flags="-n --name -l --listen -r --readonly -d --daemon -p --pidfile -L --logfile -v --verbose --trace --hide-dotfiles --username --password --expire -V --version -h --help"
    local stop_flags="-p --pidfile -h --help"
    local cmds="stop"

    # Value-taking flags in main mode.
    case "$prev" in
        -l|--listen|-p|--pidfile|-L|--logfile|--username|--password|--expire)
            return 0
            ;;
        -n|--name)
            return 0
            ;;
    esac

    # Subcommand-aware completion for "sambam stop ...".
    if [[ ${#COMP_WORDS[@]} -ge 2 && ${COMP_WORDS[1]} == "stop" ]]; then
        case "$prev" in
            -p|--pidfile)
                COMPREPLY=( $(compgen -f -- "$cur") )
                return 0
                ;;
        esac
        COMPREPLY=( $(compgen -W "$stop_flags" -- "$cur") )
        return 0
    fi

    # First argument: either subcommand or global flags/positional path.
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$cmds $global_flags" -- "$cur") )
        COMPREPLY+=( $(compgen -d -- "$cur") )
        return 0
    fi

    # Default main-mode completion: flags + directory paths.
    COMPREPLY=( $(compgen -W "$global_flags" -- "$cur") )
    COMPREPLY+=( $(compgen -d -- "$cur") )
}

complete -F _sambam_complete sambam
