# Fish completion for esops-doctor.
# Drop into ~/.config/fish/completions/ or /usr/share/fish/vendor_completions.d/.
# Generated from the urfave/cli/v3 fish template.
#
# IMPORTANT: do NOT regenerate this file by piping `esops-doctor completion fish`
# into it. The upstream urfave/cli/v3 fish template uses `%[1]` placeholders
# without the `s` verb, so fmt.Sprintf produces broken output (function names
# like `__%!_(string=esops-doctor)perform_completion`). Re-generate by hand
# using the template at
# github.com/urfave/cli/v3@<version>/autocomplete/fish_autocomplete and
# replacing every `%[1]s` (or `%[1]`) literal with `esops-doctor`. Bash and
# zsh templates use the correct `%[1]s` form and can be regenerated via the
# binary's `completion bash` / `completion zsh` subcommands.

function __esops-doctor_perform_completion
    # Extract all args except the last one
    set -l args (commandline -opc)
    # Extract the last arg (partial input)
    set -l lastArg (commandline -ct)

    set -l results ($args[1] $args[2..-1] $lastArg --generate-shell-completion 2> /dev/null)

    # Remove trailing empty lines
    for line in $results[-1..1]
        if test (string trim -- $line) = ""
            set results $results[1..-2]
        else
            break
        end
    end

    for line in $results
        if not string match -q -- "esops-doctor*" $line
            set -l parts (string split -m 1 ":" -- "$line")
            if test (count $parts) -eq 2
                printf "%s\t%s\n" "$parts[1]" "$parts[2]"
            else
                printf "%s\n" "$line"
            end
        end
    end
end

# Clear existing completions for esops-doctor
complete -c esops-doctor -e
# Register completion function
complete -c esops-doctor -f -a '(__esops-doctor_perform_completion)'
