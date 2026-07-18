import { useLayoutEffect, useRef, useState } from 'react'

export interface IndicatorRect {
  top: number
  left: number
  width: number
  height: number
}

/**
 * Measures the position of the child carrying `data-key={activeKey}` inside
 * the returned container, so callers can render a single absolutely
 * positioned "pill" that slides/resizes between items - the classic iOS
 * segmented-control / sidebar-selection animation. Re-measures on active
 * item changes and on container resize (e.g. sidebar width, text reflow).
 *
 * Pure CSS can't do this (it has no notion of "the previously active
 * sibling"), and this only works well because React keeps the same DOM
 * nodes alive across renders - one of the concrete advantages of the React
 * app over the Streamlit one, which remounts everything on each rerun.
 */
export function useSlidingIndicator<T extends HTMLElement>(activeKey: string) {
  const containerRef = useRef<T | null>(null)
  const [rect, setRect] = useState<IndicatorRect | null>(null)
  const [ready, setReady] = useState(false)

  useLayoutEffect(() => {
    const container = containerRef.current
    if (!container) return

    const update = () => {
      const active = container.querySelector<HTMLElement>(`[data-key="${CSS.escape(activeKey)}"]`)
      if (!active) {
        setRect(null)
        return
      }
      setRect({
        top: active.offsetTop,
        left: active.offsetLeft,
        width: active.offsetWidth,
        height: active.offsetHeight,
      })
    }

    update()
    // Skip the entrance transition on the very first measurement so the
    // pill doesn't visibly animate in from the top-left corner on mount.
    const raf = requestAnimationFrame(() => setReady(true))
    const resizeObserver = new ResizeObserver(update)
    resizeObserver.observe(container)
    return () => {
      resizeObserver.disconnect()
      cancelAnimationFrame(raf)
    }
  }, [activeKey])

  return { containerRef, indicatorRect: rect, indicatorReady: ready }
}
