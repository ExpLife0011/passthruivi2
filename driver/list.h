#ifndef _LIST_H_
#define _LIST_H_

BOOLEAN
IsTimeOut(
    IN PLARGE_INTEGER newtime,
    IN PLARGE_INTEGER oldtime,
    IN PLARGE_INTEGER timeout
    );


VOID
ResetMapListsSafe(
    VOID
    );


VOID
InitMapListsAndLocks(
    VOID
    );


VOID
ReleaseMapListsAndLocks(
    VOID
    );


#endif // _LIST_H_
