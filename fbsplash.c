#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "fbsplash.h"

/* Initialize the framebuffer device
 * Opens the device, gets screen information, and creates a buffer
 */
Framebuffer* fb_init(const char *fb_device) {
    // Allocate and initialize framebuffer structure
    Framebuffer *fb = calloc(1, sizeof(Framebuffer));
    if (!fb) {
        fprintf(stderr, "Failed to allocate framebuffer structure\n");
        return NULL;
    }

    // Open the framebuffer device
    fb->fd = open(fb_device, O_RDWR);
    if (fb->fd == -1) {
        fprintf(stderr, "Failed to open framebuffer device: %m\n");
        free(fb);
        return NULL;
    }

    // Get variable screen information
    if (ioctl(fb->fd, FBIOGET_VSCREENINFO, &fb->vinfo) == -1) {
        fprintf(stderr, "Failed to get variable screen info: %m\n");
        close(fb->fd);
        free(fb);
        return NULL;
    }

    // Get fixed screen information
    if (ioctl(fb->fd, FBIOGET_FSCREENINFO, &fb->finfo) == -1) {
        fprintf(stderr, "Failed to get fixed screen info: %m\n");
        close(fb->fd);
        free(fb);
        return NULL;
    }

    // Calculate total screen size in bytes
    fb->screensize = fb->vinfo.yres_virtual * fb->finfo.line_length;

    // Allocate a software buffer instead of memory mapping
    fb->buffer = malloc(fb->screensize);
    if (!fb->buffer) {
        fprintf(stderr, "Failed to allocate memory buffer\n");
        close(fb->fd);
        free(fb);
        return NULL;
    }

    // Initialize buffer to black
    memset(fb->buffer, 0, fb->screensize);

    return fb;
}

/* Set a pixel in the framebuffer
 * Handles bounds checking and pixel format
 */
void set_pixel(Framebuffer *fb, uint32_t x, uint32_t y, uint32_t color) {
    // Check if pixel is within screen bounds
    if (x >= fb->vinfo.xres || y >= fb->vinfo.yres) {
        return;
    }

    // Calculate pixel offset in buffer
    size_t location = (x + fb->vinfo.xoffset) * (fb->vinfo.bits_per_pixel / 8) +
                      (y + fb->vinfo.yoffset) * fb->finfo.line_length;

    if (location >= fb->screensize) {
        return;
    }

    // Write pixel color (currently only supports 32-bit color depth)
    if (fb->vinfo.bits_per_pixel == 32) {
        *((uint32_t*)(fb->buffer + location)) = color;
    }
}

/* Write the buffer to the framebuffer device */
void fb_flush(Framebuffer *fb) {
    if (fb && fb->buffer) {
        lseek(fb->fd, 0, SEEK_SET);
        write(fb->fd, fb->buffer, fb->screensize);
    }
}

/* Clean up framebuffer resources */
void fb_cleanup(Framebuffer *fb) {
    if (fb) {
        if (fb->buffer) {
            free(fb->buffer);
        }
        if (fb->fd >= 0) {
            close(fb->fd);
        }
        free(fb);
    }
}

/* Calculate display information for SVG rendering
 * Determines optimal SVG size and position while maintaining aspect ratio
 */
DisplayInfo* calculate_display_info(Framebuffer *fb) {
    DisplayInfo *info = calloc(1, sizeof(DisplayInfo));
    if (!info) {
        return NULL;
    }

    info->screen_width = fb->vinfo.xres;
    info->screen_height = fb->vinfo.yres;

    // Calculate SVG dimensions to fit in screen while maintaining aspect ratio
    float target_width = info->screen_width * 0.6f;  // Use 60% of screen width
    float target_height = target_width * (500.0f / 1284.0f);  // Maintain SVG aspect ratio

    // Adjust if height is too large
    if (target_height > info->screen_height * 0.6f) {
        target_height = info->screen_height * 0.6f;
        target_width = target_height * (1284.0f / 500.0f);
    }

    // Set final dimensions and calculate centering offsets
    info->svg_width = (uint32_t)target_width;
    info->svg_height = (uint32_t)target_height;
    info->x_offset = (info->screen_width - info->svg_width) / 2;
    info->y_offset = (info->screen_height - info->svg_height) / 2;

    return info;
}
