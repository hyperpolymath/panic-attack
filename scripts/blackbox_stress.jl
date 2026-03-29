#!/usr/bin/env julia
# SPDX-License-Identifier: PMPL-1.0-or-later

#=
    blackbox_stress.jl

    Black-box stress runner for panic-attack.

    Runs repeated assail/assault cycles with randomized axes, intensity, and
    probe mode, then logs stdout/stderr per run and writes a summary.json.

    Usage:
        julia blackbox_stress.jl [--runs N] [--seed N] [--build]
            [--source DIR] [--target PATH] [--outdir DIR] [--use-profile]
=#

using JSON3
using Random
using Dates

## ---------------------------------------------------------------------------
## Constants
## ---------------------------------------------------------------------------

const AXES        = ["cpu", "memory", "disk", "network", "concurrency", "time"]
const INTENSITIES = ["light", "medium", "heavy"]
const PROBES      = ["auto", "always", "never"]

## ---------------------------------------------------------------------------
## Subprocess helper
## ---------------------------------------------------------------------------

"""
    run_logged(cmd, log_dir, label) -> Int

Execute `cmd` as a subprocess.  Stdout and stderr are captured to
`<log_dir>/<label>.out` and `<log_dir>/<label>.err` respectively, each
prefixed with a header showing the timestamp, command, and exit code.
Returns the process exit code.
"""
function run_logged(cmd::Vector{String}, log_dir::String, label::String)::Int
    mkpath(log_dir)
    started = Dates.format(now(), "yyyy-mm-dd'T'HHMMSS")

    stdout_path = joinpath(log_dir, "$(label).out")
    stderr_path = joinpath(log_dir, "$(label).err")

    exitcode = try
        proc = run(pipeline(Cmd(cmd); stdout = stdout_path,
                            stderr = stderr_path); wait = true)
        proc.exitcode
    catch e
        if e isa ProcessFailedException
            e.procs[1].exitcode
        else
            1
        end
    end

    # Prepend a header into each log file.
    header = "# $(started)\n# cmd: $(join(cmd, ' '))\n# exit: $(exitcode)\n\n"
    for path in (stdout_path, stderr_path)
        existing = isfile(path) ? read(path, String) : ""
        write(path, header * existing)
    end

    return exitcode
end

## ---------------------------------------------------------------------------
## Random sampling (no StatsBase dependency)
## ---------------------------------------------------------------------------

"""
    random_sample(collection, k) -> Vector

Return `k` unique elements chosen at random from `collection`.
"""
function random_sample(collection, k::Int)
    return shuffle(collection)[1:k]
end

## ---------------------------------------------------------------------------
## Argument parsing
## ---------------------------------------------------------------------------

"""
    parse_args(args) -> NamedTuple

Manually parse CLI arguments from `args` (typically `ARGS`).
"""
function parse_args(args::Vector{String})
    runs        = 5
    seed        = nothing
    build       = false
    source      = nothing
    target      = nothing
    outdir      = "blackbox-logs"
    use_profile = false

    i = 1
    while i <= length(args)
        arg = args[i]
        if arg == "--runs" && i < length(args)
            i += 1; runs = parse(Int, args[i])
        elseif arg == "--seed" && i < length(args)
            i += 1; seed = parse(Int, args[i])
        elseif arg == "--build"
            build = true
        elseif arg == "--source" && i < length(args)
            i += 1; source = args[i]
        elseif arg == "--target" && i < length(args)
            i += 1; target = args[i]
        elseif arg == "--outdir" && i < length(args)
            i += 1; outdir = args[i]
        elseif arg == "--use-profile"
            use_profile = true
        else
            @warn "Unknown argument: $(arg)"
        end
        i += 1
    end

    return (; runs, seed, build, source, target, outdir, use_profile)
end

## ---------------------------------------------------------------------------
## Main
## ---------------------------------------------------------------------------

"""
    main() -> Int

Entry point.  Returns 0 on full success, 1 if any run failed or the binary
is missing.
"""
function main()::Int
    opts = parse_args(ARGS)

    if opts.seed !== nothing
        Random.seed!(opts.seed)
    end

    # Resolve paths relative to the repo root (one directory above scripts/).
    root   = dirname(dirname(abspath(@__FILE__)))
    source = something(opts.source, root)
    target = something(opts.target,
                       joinpath(root, "target", "debug", "examples",
                                "attack_harness"))

    # Optional build step.
    if opts.build
        if run_logged(["cargo", "build"], opts.outdir, "build-main") != 0
            return 1
        end
        if run_logged(["cargo", "build", "--example", "attack_harness"],
                      opts.outdir, "build-harness") != 0
            return 1
        end
    end

    binary = joinpath(root, "target", "debug", "panic-attack")
    if !isfile(binary)
        println(stderr, "panic-attack binary not found at $(binary)")
        return 1
    end

    failures = Vector{Dict{String,Any}}()
    reports  = Vector{String}()
    profile  = joinpath(root, "profiles", "attack-profile.example.json")

    for idx in 1:opts.runs
        n_axes    = rand(1:length(AXES))
        axes      = random_sample(AXES, n_axes)
        intensity = rand(INTENSITIES)
        duration  = rand([1, 3, 5])
        probe     = rand(PROBES)
        report    = joinpath(root, "reports",
                             "blackbox-$(round(Int, time()))-$(idx).json")

        cmd = String[
            binary,
            "assault",
            "--source", source,
            target,
            "--axes",          join(axes, ","),
            "--intensity",     intensity,
            "--duration",      string(duration),
            "--output",        report,
            "--output-format", "json",
            "--probe",         probe,
        ]

        if opts.use_profile && isfile(profile)
            append!(cmd, ["--profile", profile])
        end

        label = "assault-$(idx)"
        code  = run_logged(cmd, opts.outdir, label)

        if code != 0
            push!(failures, Dict{String,Any}("run" => idx, "exit_code" => code))
        else
            push!(reports, report)
        end
    end

    # Write summary JSON.
    summary = Dict{String,Any}(
        "runs"     => opts.runs,
        "failures" => failures,
        "reports"  => reports,
    )
    mkpath(opts.outdir)
    open(joinpath(opts.outdir, "summary.json"), "w") do io
        JSON3.pretty(io, summary)
    end

    if !isempty(failures)
        println("$(length(failures)) runs failed. See $(opts.outdir)/summary.json")
        return 1
    end

    println("All $(opts.runs) runs completed successfully. Logs: $(opts.outdir)")
    return 0
end

## ---------------------------------------------------------------------------
## Entry point
## ---------------------------------------------------------------------------

exit(main())
