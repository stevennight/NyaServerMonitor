# 自定义主题包

把一个主题文件夹放进 `data/theme/`（例如 `data/theme/my-theme/`），控制器无需重启即可在下次
打开「主题」下拉菜单时读取并使用它。

## 目录结构

```
data/theme/my-theme/
  theme.json   # 元信息（必需）
  style.css    # 颜色变量（必需）
```

## theme.json

```json
{
  "name": "我的主题",
  "description": "一句话描述",
  "author": "你的名字",
  "preview": ["#0c1115", "#141d23", "#49d18d"]
}
```

- `name`（必需）：显示在主题下拉菜单里的名字。
- `description`、`author`：可选，仅用于展示。
- `preview`：可选，2-4 个十六进制颜色，用于将来的主题预览色块（背景色、面板色、强调色）。

文件夹名即为主题 id，只能包含小写字母、数字和短横线（`^[a-z][a-z0-9-]{1,47}$`），且必须以字母开头。

## style.css

只需要写一条规则，覆盖下面这组 CSS 变量（可以参考任意一个内置主题的 `style.css` 作为模板，
例如 `data/theme/hacker-matrix/style.css`）：

```css
html[data-theme-pack="my-theme"]{
  color-scheme: dark; /* 或 light */
  --app-font: ...;      /* 可选：整体字体 */
  --app-bg-image: ...;  /* 可选：body 背景（渐变/纹理，无需图片文件，会随内容滚动固定） */
  --app-overlay-image: ...;  /* 可选：铺在所有卡片/面板之上的全屏纹理（扫描线、噪点、星空等），
                                 z-index 在弹窗（10）和提示条（20）之下，不挡点击 */
  --app-overlay-size: cover;    /* 可选：纹理平铺尺寸，如 "16px 16px"（配合小圆点/网格纹理用） */
  --app-overlay-opacity: .5;    /* 可选：纹理不透明度，0-1 */
  --app-overlay-blend: normal;  /* 可选：纹理混合模式，如 multiply/screen/soft-light */
  --app-heading-glow: ...;      /* 可选：标题和品牌图标的 text-shadow 发光效果 */
  --bg: ...; --panel: ...; --panel-2: ...; --line: ...; --text: ...; --muted: ...;
  --green: ...; --yellow: ...; --red: ...; --blue: ...; --shadow: ...;
  --theme-side-bg: ...; --theme-header-bg: ...; --theme-input-bg: ...; --theme-track: ...;
  --theme-mono: ...; --theme-row-line: ...; --theme-hover-border: ...;
  --theme-primary-text: ...; --theme-mark-text: ...; --theme-tag: ...; --theme-badge-bg: ...;
  --theme-notice-border: ...; --theme-notice-bg: ...; --theme-notice-text: ...;
  --theme-token-bg: ...; --theme-modal-backdrop: ...; --theme-overlay-shadow: ...;
  --theme-toast-bg: ...; --theme-toast-border: ...; --theme-toast-text: ...;
  --theme-error-bg: ...; --theme-error-border: ...; --theme-error-text: ...;
  --theme-auth-accent: ...; --theme-subtle-surface: ...;
  --theme-map-surface: ...; --theme-map-border: ...; --theme-map-grid: ...; --theme-map-empty-bg: ...;
  --map-ocean: ...; --map-land: ...; --map-land-muted: ...; --map-border: ...; --map-grid: ...;
  --map-label: ...; --map-land-hover: ...; --map-border-hover: ...; --map-marker-text: ...; --map-marker-count-bg: ...;
  --theme-switch-bg: ...; --theme-switch-active-bg: ...;
}
```

只允许覆盖 CSS 变量（以及可选的 `--app-font` / `--app-bg-image`），不要在这个文件里写其他选择器 —
这样再离谱的配色最多是不好看，也不会破坏页面布局。

主题文件通过 `GET /themes/<id>/<文件名>` 提供，`style.css` 里也可以用相对路径引用同目录下的其他
文件（比如 `assets/font.woff2`），控制器会一并读取。

## 删除 / 替换内置主题

`data/theme/` 里的 10 个内置主题只在该文件夹不存在时才会被重新创建。可以放心编辑、替换或删除
其中任意一个，重启程序不会覆盖你的修改。
