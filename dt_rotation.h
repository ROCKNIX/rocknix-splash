#ifndef DT_ROTATION_H
#define DT_ROTATION_H

/* Get display rotation from device tree
 * Recursively searches /proc/device-tree for rotation property
 * Returns: rotation angle in degrees (0, 90, 180, or 270)
 */
int get_display_rotation(void);

#endif
