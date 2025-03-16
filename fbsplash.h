#ifndef FBSPLASH_H
#define FBSPLASH_H

#include <stdint.h>
#include <linux/fb.h>

/* Framebuffer structure holding device information and buffer
 * fd: File descriptor for the framebuffer device
 * buffer: Software buffer for drawing operations
 * vinfo: Variable screen information (resolution, bit depth, etc.)
 * finfo: Fixed screen information (memory length, line length, etc.)
 * screensize: Total size of the framebuffer in bytes
 */
typedef struct {
    int fd;
    uint8_t *buffer;
    struct fb_var_screeninfo vinfo;
    struct fb_fix_screeninfo finfo;
    size_t screensize;
} Framebuffer;

/* Display information structure for SVG rendering
 * Contains screen and SVG dimensions and offsets for centering
 */
typedef struct {
    uint32_t screen_width;   // Width of the screen in pixels
    uint32_t screen_height;  // Height of the screen in pixels
    uint32_t svg_width;      // Width of the scaled SVG
    uint32_t svg_height;     // Height of the scaled SVG
    uint32_t x_offset;       // X offset for centering SVG
    uint32_t y_offset;       // Y offset for centering SVG
} DisplayInfo;

/* Initialize the framebuffer device
 * Returns: Pointer to initialized Framebuffer structure or NULL on failure
 */
Framebuffer* fb_init(const char *fb_device);

/* Clean up and free framebuffer resources */
void fb_cleanup(Framebuffer *fb);

/* Set a single pixel in the framebuffer
 * color: 32-bit RGBA color value
 */
void set_pixel(Framebuffer *fb, uint32_t x, uint32_t y, uint32_t color);

/* Blend a pixel with alpha transparency
 * alpha: 0.0 (transparent) to 1.0 (opaque)
 */
void blend_pixel(Framebuffer *fb, uint32_t x, uint32_t y, uint32_t color, float alpha);

/* Write the internal buffer to the framebuffer device */
void fb_flush(Framebuffer *fb);

/* Calculate display information for SVG rendering
 * Returns: Pointer to DisplayInfo structure with calculated values
 */
DisplayInfo* calculate_display_info(Framebuffer *fb);

#endif
