import { Moon, Sun } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { useTheme } from '@/hooks/useTheme'

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme()
  return (
    <Button
      type="button"
      variant="outline"
      size="icon"
      onClick={toggleTheme}
      aria-label={theme === 'dark' ? 'Passa al tema chiaro' : 'Passa al tema scuro'}
      title={theme === 'dark' ? 'Tema chiaro' : 'Tema scuro'}
    >
      {theme === 'dark' ? (
        <Sun className="h-4 w-4 animate-spring-in" key="sun" />
      ) : (
        <Moon className="h-4 w-4 animate-spring-in" key="moon" />
      )}
    </Button>
  )
}
