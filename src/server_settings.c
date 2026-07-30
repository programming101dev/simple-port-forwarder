#include "server_settings.h"
#include "settings.h"
#include <p101_env/env.h>
#include <p101_error/error.h>

#define MAX_NANOSECONDS 999999999L    // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum,readability-magic-numbers)

void check_settings(const struct p101_env *env, struct p101_error *err, const struct settings *sets)
{
    P101_TRACE_SCOPE(env);

    if(sets->min_seconds > sets->max_seconds)
    {
        P101_ERROR_RAISE_USER(err, "min-seconds must be <= max-seconds", 1);
        goto done;
    }

    if(sets->min_nanoseconds > sets->max_nanoseconds)
    {
        P101_ERROR_RAISE_USER(err, "min-nanoseconds must be <= max-nanoseconds", 2);
        goto done;
    }

    if(sets->min_bytes > sets->max_bytes)
    {
        P101_ERROR_RAISE_USER(err, "min-bytes must be <= max-bytes", 3);
        goto done;
    }

    if(sets->min_seconds < 0 || sets->max_seconds < 0)
    {
        P101_ERROR_RAISE_USER(err, "delay seconds must be >= 0", 4);
        goto done;
    }

    if(sets->min_nanoseconds < 0 || sets->max_nanoseconds > MAX_NANOSECONDS)
    {
        P101_ERROR_RAISE_USER(err, "delay nanoseconds must be in the range 0..999999999", 5);
        goto done;
    }

done:
    return;
}
