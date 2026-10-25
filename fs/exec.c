static int do_execveat_common(int fd, struct filename *filename,
                              struct user_arg_ptr argv,
                              struct user_arg_ptr envp,
                              int flags)
{
        int retval;

        /*
         * We move the actual failure in case of RLIMIT_NPROC excess from
         * set*uid() to execve() because too many poorly written programs
         * don't check setuid() return code.  Here we additionally recheck
         * whether NPROC limit is still exceeded.
         */
        if ((current->flags & PF_NPROC_EXCEEDED) &&
            is_rlimit_overlimit(current_ucounts(), UCOUNT_RLIMIT_NPROC, rlimit(RLIMIT_NPROC)))
                return -EAGAIN;

        /* We're below the limit (still or again), so we don't want to make
         * further execve() calls fail. */
        current->flags &= ~PF_NPROC_EXCEEDED;

        CLASS(bprm, bprm)(fd, filename, flags);
        if (IS_ERR(bprm))
                return PTR_ERR(bprm);

        retval = count(argv, MAX_ARG_STRINGS);
        if (retval < 0)
                return retval;
        bprm->argc = retval;

        retval = count(envp, MAX_ARG_STRINGS);
        if (retval < 0)
                return retval;
        bprm->envc = retval;

        retval = bprm_stack_limits(bprm);
        if (retval < 0)
                return retval;

        retval = copy_string_kernel(bprm->filename, bprm);
        if (retval < 0)
                return retval;
        bprm->exec = bprm->p;

        retval = copy_strings(bprm->envc, envp, bprm);
        if (retval < 0)
                return retval;

        retval = copy_strings(bprm->argc, argv, bprm);
        if (retval < 0)
                return retval;

        /*
         * When argv is empty, add an empty string ("") as argv[0] to
         * ensure confused userspace programs that start processing
         * from argv[1] won't end up walking envp. See also
         * bprm_stack_limits().
         */
        if (bprm->argc == 0) {
                retval = copy_string_kernel("", bprm);
                if (retval < 0)
                        return retval;
                bprm->argc = 1;

                pr_warn_once("process '%s' launched '%s' with NULL argv: empty string added\n",
                             current->comm, bprm->filename);
        }

        return bprm_execve(bprm);
}