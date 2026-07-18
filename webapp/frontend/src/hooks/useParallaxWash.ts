import { useEffect, type RefObject } from 'react'

/**
 * Subtly nudges the `.app-shell::before` ambient wash gradient in response
 * to pointer position, via the --wash-x/--wash-y custom properties consumed
 * in index.css. Purely decorative and cheap (a single transform, throttled
 * to one update per animation frame) - skipped entirely for touch/coarse
 * pointers and whenever the user prefers reduced motion.
 */
export function useParallaxWash(ref: RefObject<HTMLElement | null>) {
  useEffect(() => {
    const el = ref.current
    if (!el) return

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const canHover = window.matchMedia('(hover: hover) and (pointer: fine)').matches
    if (reduceMotion || !canHover) return

    let raf = 0
    function handleMove(event: PointerEvent) {
      if (raf) return
      raf = requestAnimationFrame(() => {
        raf = 0
        const x = (event.clientX / window.innerWidth - 0.5) * 2
        const y = (event.clientY / window.innerHeight - 0.5) * 2
        el?.style.setProperty('--wash-x', x.toFixed(3))
        el?.style.setProperty('--wash-y', y.toFixed(3))
      })
    }

    window.addEventListener('pointermove', handleMove, { passive: true })
    return () => {
      window.removeEventListener('pointermove', handleMove)
      if (raf) cancelAnimationFrame(raf)
    }
  }, [ref])
}
