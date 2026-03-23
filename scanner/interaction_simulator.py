"""
scanner/interaction_simulator.py

InteractionSimulator — Playwright user gesture simulation untuk event handler
baru 2025 yang butuh interaksi sebelum terpicu.

Setiap 'interaction_type' di NewEventHandlerEngine2025 punya simulator-nya
sendiri di sini. Engine v3 memakai ini saat --test-new-events aktif.

Interaction types yang di-support:
  popover          → klik tombol yang buka popover (onbeforetoggle)
  scroll           → scroll elemen ke bawah lalu berhenti (onscrollend)
  clipboard        → Ctrl+A → Ctrl+C / Ctrl+X (oncopy, oncut)
  mouse_move       → gerakkan mouse ke atas elemen (onpointerrawupdate)
  mouse_enter_leave→ masuk → keluar elemen (onpointerleave)
  css_animation    → start animasi CSS lalu cancel paksa (onanimationcancel)
  css_transition   → trigger transition lalu cancel (ontransitioncancel)
  content_visibility→ scroll ke elemen yg pakai content-visibility:auto
  details          → toggle elemen <details> (ontoggle)
  none             → langsung (auto-fire saat load)
  navigation       → tidak bisa disimulasikan di headless (onpageswap dll)
"""

import asyncio
from typing import Optional, List, Tuple
from utils.logger import debug


# ─── Timeout per tipe interaksi (ms) ─────────────────────────────────────────
INTERACTION_TIMEOUT = {
    "popover":           3000,
    "scroll":            3000,
    "clipboard":         2500,
    "mouse_move":        3000,
    "mouse_enter_leave": 3000,
    "css_animation":     3500,
    "css_transition":    3000,
    "content_visibility":3500,
    "details":           2000,
    "none":              2000,
    "navigation":        1000,
    "csp":               2000,
}

# Interaction types yang TIDAK bisa disimulasikan di headless
CANNOT_SIMULATE = {"navigation"}


class InteractionSimulator:
    """
    Kumpulan Playwright automation sequence untuk tiap interaction_type.
    Semua method async dan menerima Playwright page object.

    Cara pakai:
        sim = InteractionSimulator()
        fired = await sim.trigger(page, "popover", timeout_ms=2500)
    """

    async def trigger(
        self,
        page,
        interaction_type: str,
        timeout_ms: int = 2500,
    ) -> bool:
        """
        Jalankan simulasi interaksi yang sesuai.
        Return True jika alert() terpicu selama simulasi.
        """
        if interaction_type in CANNOT_SIMULATE:
            debug(f"[sim] {interaction_type} tidak bisa disimulasikan di headless")
            return False

        alert_fired = []

        async def on_dialog(dialog):
            alert_fired.append(dialog.message)
            await dialog.dismiss()

        page.on("dialog", on_dialog)
        try:
            fn = getattr(self, f"_sim_{interaction_type}", self._sim_none)
            await fn(page, timeout_ms)
            # Tunggu sebentar buat async event settle
            await page.wait_for_timeout(300)
        except Exception as e:
            debug(f"[sim] {interaction_type} error: {e}")
        finally:
            page.remove_listener("dialog", on_dialog)

        return bool(alert_fired)

    # ─── Simulasi per tipe ────────────────────────────────────────────────────

    async def _sim_none(self, page, timeout_ms):
        """Auto-fire — langsung cek tanpa interaksi."""
        await page.wait_for_timeout(min(timeout_ms, 800))

    async def _sim_details(self, page, timeout_ms):
        """
        Toggle elemen <details> — ontoggle.
        Cek apakah ada details yang sudah open; kalau belum, klik summary-nya.
        """
        await page.wait_for_timeout(400)
        # Coba klik summary untuk toggle
        try:
            summaries = await page.query_selector_all("summary")
            for s in summaries[:3]:
                await s.click()
                await page.wait_for_timeout(300)
        except Exception:
            pass
        # Coba toggle via JS juga
        try:
            await page.evaluate("""
                document.querySelectorAll('details').forEach(d => {
                    d.open = !d.open;
                });
            """)
            await page.wait_for_timeout(400)
        except Exception:
            pass

    async def _sim_popover(self, page, timeout_ms):
        """
        Klik tombol yang punya popovertarget — onbeforetoggle.
        Tombol bisa <button> atau <input> dengan atribut popovertarget.
        """
        await page.wait_for_timeout(300)
        try:
            # Cari semua elemen dengan atribut popovertarget
            triggers = await page.query_selector_all("[popovertarget]")
            for trigger in triggers[:3]:
                try:
                    await trigger.click(timeout=1000)
                    await page.wait_for_timeout(400)
                except Exception:
                    pass
            # Fallback: coba showPopover() via JS langsung
            if not triggers:
                await page.evaluate("""
                    document.querySelectorAll('[popover]').forEach(el => {
                        try { el.showPopover(); } catch(e) {}
                    });
                """)
                await page.wait_for_timeout(400)
        except Exception as e:
            debug(f"[sim:popover] {e}")

    async def _sim_scroll(self, page, timeout_ms):
        """
        Scroll elemen scrollable ke bawah lalu berhenti — onscrollend.
        onscrollend dipicu beberapa ms setelah scroll berhenti.
        """
        await page.wait_for_timeout(200)
        try:
            # Cari elemen yang overflow/scrollable
            scrollables = await page.query_selector_all(
                '[onscrollend], [style*="overflow"]'
            )
            for el in scrollables[:3]:
                try:
                    # Scroll via evaluate pada elemen spesifik
                    await el.evaluate("""el => {
                        el.scrollTop = el.scrollHeight;
                    }""")
                    await page.wait_for_timeout(500)
                    await el.evaluate("el => { el.scrollTop = 0; }")
                    await page.wait_for_timeout(500)
                except Exception:
                    pass
            # Fallback: scroll window
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(500)
            await page.evaluate("window.scrollTo(0, 0)")
            await page.wait_for_timeout(500)
        except Exception as e:
            debug(f"[sim:scroll] {e}")

    async def _sim_clipboard(self, page, timeout_ms):
        """
        Select all + Ctrl+C + Ctrl+X — oncopy, oncut.
        Coba focus ke elemen yang punya handler dulu.
        """
        await page.wait_for_timeout(200)
        try:
            # Focus ke body dulu
            await page.keyboard.press("Tab")
            await page.wait_for_timeout(100)

            # Ctrl+A (select all)
            await page.keyboard.press("Control+a")
            await page.wait_for_timeout(200)

            # Ctrl+C (copy) — trigger oncopy
            await page.keyboard.press("Control+c")
            await page.wait_for_timeout(300)

            # Ctrl+X (cut) — trigger oncut
            # Re-select dulu karena cut menghapus selection
            await page.keyboard.press("Control+a")
            await page.wait_for_timeout(100)
            await page.keyboard.press("Control+x")
            await page.wait_for_timeout(300)

            # Coba juga focus ke textarea/input spesifik
            inputs = await page.query_selector_all("textarea, input[type=text], [oncopy], [oncut]")
            for inp in inputs[:3]:
                try:
                    await inp.click()
                    await page.wait_for_timeout(100)
                    await page.keyboard.press("Control+a")
                    await page.wait_for_timeout(100)
                    await page.keyboard.press("Control+c")
                    await page.wait_for_timeout(200)
                    await page.keyboard.press("Control+x")
                    await page.wait_for_timeout(200)
                except Exception:
                    pass
        except Exception as e:
            debug(f"[sim:clipboard] {e}")

    async def _sim_mouse_move(self, page, timeout_ms):
        """
        Gerakkan mouse di atas elemen — onpointerrawupdate, onmousemove.
        """
        await page.wait_for_timeout(200)
        try:
            # Gerak ke tengah halaman dulu
            vp = page.viewport_size or {"width": 1280, "height": 720}
            cx = vp["width"] // 2
            cy = vp["height"] // 2

            await page.mouse.move(cx, cy)
            await page.wait_for_timeout(100)

            # Gerak kecil-kecil untuk trigger onpointerrawupdate
            for i in range(8):
                await page.mouse.move(cx + (i % 4) * 5, cy + (i // 4) * 5)
                await page.wait_for_timeout(40)

            # Coba juga gerak ke elemen yang punya handler
            targets = await page.query_selector_all(
                "[onpointerrawupdate], [onmousemove], [onmouseover], [onpointerover]"
            )
            for el in targets[:3]:
                try:
                    box = await el.bounding_box()
                    if box:
                        ex = box["x"] + box["width"] / 2
                        ey = box["y"] + box["height"] / 2
                        await page.mouse.move(ex, ey)
                        await page.wait_for_timeout(100)
                        for i in range(6):
                            await page.mouse.move(ex + i * 4, ey + i * 3)
                            await page.wait_for_timeout(40)
                except Exception:
                    pass
        except Exception as e:
            debug(f"[sim:mouse_move] {e}")

    async def _sim_mouse_enter_leave(self, page, timeout_ms):
        """
        Masuk ke elemen lalu keluar — onpointerleave, onmouseleave.
        """
        await page.wait_for_timeout(200)
        try:
            targets = await page.query_selector_all(
                "[onpointerleave], [onmouseleave], [onpointerout], [onmouseout]"
            )
            if not targets:
                # Fallback: coba semua div/span yang ada
                targets = await page.query_selector_all("div, span, p")

            for el in targets[:3]:
                try:
                    box = await el.bounding_box()
                    if box:
                        cx = box["x"] + box["width"] / 2
                        cy = box["y"] + box["height"] / 2
                        # Masuk ke elemen
                        await page.mouse.move(cx, cy)
                        await page.wait_for_timeout(200)
                        # Keluar dari elemen (gerak ke atas/luar batas)
                        await page.mouse.move(cx, box["y"] - 20)
                        await page.wait_for_timeout(300)
                except Exception:
                    pass
        except Exception as e:
            debug(f"[sim:mouse_enter_leave] {e}")

    async def _sim_css_animation(self, page, timeout_ms):
        """
        Jalankan CSS animation lalu batalkan — onanimationcancel.
        Di headless Chromium, display:none membatalkan animasi compositor.
        """
        await page.wait_for_timeout(400)
        try:
            # Cari elemen dengan animasi
            animated = await page.query_selector_all(
                '[onanimationcancel], [style*="animation"]'
            )
            for el in animated[:3]:
                try:
                    # Metode 1: display none untuk cancel
                    await el.evaluate("el => { el.style.display = 'none'; }")
                    await page.wait_for_timeout(200)
                    await el.evaluate("el => { el.style.display = ''; }")
                    await page.wait_for_timeout(200)
                    # Metode 2: ubah animation-name
                    await el.evaluate("el => { el.style.animationName = 'none'; }")
                    await page.wait_for_timeout(200)
                    await el.evaluate("el => { el.style.animationName = ''; }")
                    await page.wait_for_timeout(200)
                except Exception:
                    pass
            # Fallback via JS global
            await page.evaluate("""
                document.querySelectorAll('*').forEach(el => {
                    const style = getComputedStyle(el);
                    if (style.animationName && style.animationName !== 'none') {
                        const orig = el.style.animationName;
                        el.style.animationName = 'none';
                        setTimeout(() => { el.style.animationName = orig; }, 100);
                    }
                });
            """)
            await page.wait_for_timeout(500)
        except Exception as e:
            debug(f"[sim:css_animation] {e}")

    async def _sim_css_transition(self, page, timeout_ms):
        """
        Trigger CSS transition lalu batalkan — ontransitioncancel.
        """
        await page.wait_for_timeout(300)
        try:
            targets = await page.query_selector_all("[ontransitioncancel], [class]")
            for el in targets[:3]:
                try:
                    # Ubah warna/opacity untuk trigger transition lalu batalkan
                    await el.evaluate("""el => {
                        const orig = el.style.color;
                        el.style.color = 'red';
                        setTimeout(() => {
                            // Batalkan sebelum selesai
                            el.style.transitionDuration = '0s';
                            el.style.color = orig;
                        }, 50);
                    }""")
                    await page.wait_for_timeout(300)
                except Exception:
                    pass
        except Exception as e:
            debug(f"[sim:css_transition] {e}")

    async def _sim_content_visibility(self, page, timeout_ms):
        """
        Scroll ke elemen yang pakai content-visibility:auto.
        oncontentvisibilityautostatechange dipicu saat elemen masuk/keluar viewport.
        """
        await page.wait_for_timeout(300)
        try:
            targets = await page.query_selector_all(
                "[oncontentvisibilityautostatechange], [style*='content-visibility']"
            )
            for el in targets[:3]:
                try:
                    # Scroll elemen ke dalam viewport
                    await el.scroll_into_view_if_needed(timeout=1000)
                    await page.wait_for_timeout(400)
                    # Scroll keluar viewport lagi
                    await page.evaluate("window.scrollTo(0, 0)")
                    await page.wait_for_timeout(300)
                    # Scroll kembali masuk
                    await el.scroll_into_view_if_needed(timeout=1000)
                    await page.wait_for_timeout(400)
                except Exception:
                    pass
            # Fallback: toggle visibility via JS
            await page.evaluate("""
                document.querySelectorAll('[style*="content-visibility"]').forEach(el => {
                    el.style.contentVisibility = 'visible';
                    setTimeout(() => { el.style.contentVisibility = 'auto'; }, 100);
                });
            """)
            await page.wait_for_timeout(400)
        except Exception as e:
            debug(f"[sim:content_visibility] {e}")

    # ─── Batch trigger: coba semua strategi untuk satu halaman ───────────────

    async def trigger_all_strategies(self, page, timeout_ms: int = 4000) -> bool:
        """
        Jalankan SEMUA strategi sekaligus untuk satu halaman.
        Berguna saat interaction_type tidak diketahui (misalnya DOM XSS generik).
        Return True jika ada yang trigger alert().
        """
        alert_fired = []

        async def on_dialog(dialog):
            alert_fired.append(True)
            await dialog.dismiss()

        page.on("dialog", on_dialog)
        try:
            strategies = [
                self._sim_none,
                self._sim_details,
                self._sim_popover,
                self._sim_scroll,
                self._sim_clipboard,
                self._sim_mouse_move,
                self._sim_mouse_enter_leave,
                self._sim_content_visibility,
                self._sim_css_animation,
                self._sim_css_transition,
            ]
            for fn in strategies:
                if alert_fired:
                    break
                try:
                    await fn(page, timeout_ms // len(strategies))
                    await page.wait_for_timeout(150)
                except Exception:
                    pass
        finally:
            page.remove_listener("dialog", on_dialog)

        return bool(alert_fired)
