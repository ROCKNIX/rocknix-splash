#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "fbsplash.h"
#include "svg_parser.h"
#include "svg_renderer.h"
#include "dt_rotation.h"

/*
 * SVG path data for rendering the logo
 * Contains the path data for each component of the logo
 * Index meaning:
 * 0: "R" in logo
 * 1: "O" in logo
 * 2: "C" in logo
 * 3: "K" in logo
 * 4: "N" in logo
 * 5: "I" in logo
 * 6: "X" in logo
 */
const char *svg_paths[] = {
    "M -0.002 140.106 L -0.002 359.628 L 27.138 359.628 L 27.138 270.09 L 47.626 270.09 L 115.612 359.628 L 150.077 359.628 L 77.701 267.695 C 112.29 262.506 133.445 239.357 133.445 204.499 C 133.445 164.719 105.902 140.106 62.269 140.106 L -0.002 140.106 Z M 27.138 161.925 L 54.944 161.925 C 86.613 161.925 105.368 178.024 105.368 204.499 C 105.368 230.975 86.613 247.073 54.944 247.073 L 27.138 247.073 L 27.138 161.925 Z",
    "M 166.036 250 C 166.036 313.329 215.268 363.886 276.734 363.886 C 338.2 363.886 387.424 313.329 387.424 250 C 387.424 186.671 338.2 136.116 276.734 136.116 C 215.268 136.116 166.036 186.671 166.036 250 Z M 195.306 250 C 195.306 200.375 230.561 162.325 276.734 162.325 C 322.899 162.325 358.154 200.375 358.154 250 C 358.154 299.625 322.899 337.676 276.734 337.676 C 230.561 337.676 195.306 299.625 195.306 250 Z",
    "M 530.178 363.886 C 557.45 363.886 582.461 355.504 600.557 341.801 L 586.99 319.715 C 572.619 331.023 552.928 337.144 531.905 337.144 C 478.957 337.144 443.965 299.093 443.965 250 C 443.965 200.907 478.957 162.857 531.905 162.857 C 552.928 162.857 572.619 168.977 586.99 180.285 L 600.557 158.2 C 582.461 144.497 557.45 136.116 530.178 136.116 C 463.254 136.116 414.432 185.874 414.432 250 C 414.432 314.128 463.254 363.886 530.178 363.886 Z",
    "M 661.357 359.628 L 661.357 262.108 L 762.073 359.628 L 799.853 359.628 L 685.438 247.872 L 788.145 140.106 L 754.353 140.106 L 661.357 237.894 L 661.357 140.106 L 634.217 140.106 L 634.217 359.628 L 661.357 359.628 Z",
    "M 821.944 140.106 L 821.944 359.628 L 849.084 359.628 L 849.084 186.006 L 960.038 359.628 L 987.178 359.628 L 987.178 140.106 L 960.038 140.106 L 960.038 313.861 L 849.084 140.106 L 821.944 140.106 Z",
    "M 1034.814 140.106 L 1034.814 359.627 L 1061.955 359.627 L 1061.955 140.106 L 1034.814 140.106 Z",
    "M 1116.9 359.628 L 1183.554 264.768 L 1250.208 359.628 L 1284 359.628 L 1200.45 241.219 L 1270.96 140.106 L 1238.369 140.106 L 1183.554 218.469 L 1128.74 140.106 L 1096.141 140.106 L 1166.658 241.219 L 1083.109 359.628 L 1116.9 359.628 Z"
};

/* Color definitions for each path component
 * First 4 paths are red (brand color)
 * Last 3 paths are gray (secondary color)
 */
const char *svg_colors[] = {
    "rgb(255,85,85)",  // Red
    "rgb(255,85,85)",  // Red
    "rgb(255,85,85)",  // Red
    "rgb(255,85,85)",  // Red
    "rgb(85,85,85)",   // Gray
    "rgb(85,85,85)",   // Gray
    "rgb(85,85,85)"    // Gray
};

#define NUM_PATHS (sizeof(svg_paths) / sizeof(svg_paths[0]))

/*
 * Main program entry point
 */
int main(void) {
    const char *fb_device = "/dev/fb0";

    // Get rotation from device tree
    int rotation = get_display_rotation();

    // Check framebuffer device accessibility
    if (access(fb_device, R_OK | W_OK) != 0) {
        fprintf(stderr, "Cannot access %s: %s\n", fb_device, strerror(errno));
        return 1;
    }

    // Initialize framebuffer
    Framebuffer *fb = fb_init(fb_device);
    if (!fb) {
        fprintf(stderr, "Failed to initialize framebuffer\n");
        return 1;
    }

    // Calculate display parameters
    DisplayInfo *display_info = calculate_display_info(fb);
    if (!display_info) {
        fprintf(stderr, "Failed to calculate display information\n");
        fb_cleanup(fb);
        return 1;
    }

    // Clear screen to black
    for (uint32_t y = 0; y < fb->vinfo.yres; y++) {
        for (uint32_t x = 0; x < fb->vinfo.xres; x++) {
            set_pixel(fb, x, y, 0x00000000);
        }
    }

    // Process and render each path component
    for (size_t i = 0; i < NUM_PATHS; i++) {
        SVGPath *svg = parse_svg_path(svg_paths[i], svg_colors[i]);
        if (!svg) {
            fprintf(stderr, "Failed to parse SVG path %zu\n", i);
            continue;
        }

        // Apply rotation from device tree if specified
        if (rotation)
            rotate_svg_path(svg, rotation);

        // Render the path
        render_svg_path(fb, svg, display_info);
        free_svg_path(svg);
    }

    // Clean up
    free(display_info);
    fb_cleanup(fb);

    return 0;
}
