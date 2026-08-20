/* 空占位：busybox 部分 applet 会 #include <linux/vt.h>，BPF 无 VT 子系统，
 * 不定义任何常量——用点均有 #ifdef VT_* 保护，自然裁剪。 */
