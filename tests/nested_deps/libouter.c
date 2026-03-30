/* Outer library — DT_NEEDs libinner.so (both encrypted).
 * Tests nested/transitive DT_NEEDED resolution via LD_PRELOAD. */

extern int inner_square(int);
extern int inner_double(int);

int outer_sum_of_squares(int a, int b) {
    return inner_square(a) + inner_square(b);
}

int outer_quad(int x) {
    return inner_double(inner_double(x));
}
