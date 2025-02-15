#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include "dt_rotation.h"

/* Path to device tree directory */
#define DEVICE_TREE_PATH "/proc/device-tree"
#define MAX_PATH_LEN 1024

/* Internal function to search directory recursively */
static int search_rotation_in_dir(const char *dir_path) {
    DIR *dir;
    struct dirent *entry;
    char full_path[MAX_PATH_LEN];
    unsigned char rotation_bytes[4];
    int rotation = 0;
    FILE *fp;

    dir = opendir(dir_path);
    if (!dir) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        if (entry->d_type == DT_DIR) {
            /* Recursively search subdirectory */
            rotation = search_rotation_in_dir(full_path);
            if (rotation != 0) {
                closedir(dir);
                return rotation;
            }
        } else if (strcmp(entry->d_name, "rotation") == 0) {
            fp = fopen(full_path, "r");
            if (fp) {
                if (fread(rotation_bytes, 1, 4, fp) == 4) {
                    /* Convert big-endian bytes to integer */
                    rotation = (rotation_bytes[0] << 24) |
                             (rotation_bytes[1] << 16) |
                             (rotation_bytes[2] << 8) |
                             (rotation_bytes[3]);

                    /* Normalize rotation to 90-degree increments */
                    rotation = rotation % 360;
                    if (rotation < 0) {
                        rotation += 360;
                    }
                    rotation = (rotation / 90) * 90;

                    fclose(fp);
                    closedir(dir);
                    return rotation;
                }
                fclose(fp);
            }
        }
    }

    closedir(dir);
    return 0;
}

/* Get display rotation from device tree
 * Returns: rotation angle in degrees (0, 90, 180, or 270)
 *
 * This function recursively traverses the device tree directory
 * structure looking for a file named "rotation". When found, it
 * reads a 4-byte big-endian integer value and normalizes it to
 * 0, 90, 180, or 270 degrees.
 */
int get_display_rotation(void) {
    return search_rotation_in_dir(DEVICE_TREE_PATH);
}
