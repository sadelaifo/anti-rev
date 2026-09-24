int validate_range(int val, int lo, int hi) {
    return val >= lo && val <= hi;
}

int validate_positive(int val) {
    return val > 0;
}
