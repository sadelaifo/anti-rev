/*
 * Unencrypted 3rd-party bridge library.
 * DT_NEEDs libmiddle.so (encrypted).
 *
 * Simulates an unencrypted intermediary between the exe and
 * encrypted business logic.
 */

extern int middle_value(void);
extern int middle_load_inner(void);

int bridge_get_value(void)
{
    return middle_value();
}

int bridge_get_inner(void)
{
    return middle_load_inner();
}
