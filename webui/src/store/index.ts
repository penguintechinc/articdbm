import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type Theme = 'light' | 'dark' | 'auto';

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  avatar_url?: string;
}

export interface AppState {
  // User state
  user: User | null;
  setUser: (user: User | null) => void;
  clearUser: () => void;

  // Theme state
  theme: Theme;
  setTheme: (theme: Theme) => void;

  // Sidebar state
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  toggleSidebar: () => void;

  // Notifications state
  notifications: Notification[];
  addNotification: (notification: Omit<Notification, 'id'>) => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;

  // Loading state
  isLoading: boolean;
  setLoading: (loading: boolean) => void;

  // Error state
  error: string | null;
  setError: (error: string | null) => void;

  // Settings
  locale: string;
  setLocale: (locale: string) => void;
}

export interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  description?: string;
  duration?: number;
  action?: {
    label: string;
    onClick: () => void;
  };
  timestamp: number;
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      // User state
      user: null,
      setUser: (user) => set({ user }),
      clearUser: () => set({ user: null }),

      // Theme state
      theme: 'auto',
      setTheme: (theme) => set({ theme }),

      // Sidebar state
      sidebarOpen: true,
      setSidebarOpen: (open) => set({ sidebarOpen: open }),
      toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),

      // Notifications state
      notifications: [],
      addNotification: (notification) =>
        set((state) => {
          const id = `${Date.now()}-${Math.random()}`;
          const newNotification: Notification = {
            ...notification,
            id,
            timestamp: Date.now(),
          };

          const duration = notification.duration || 5000;
          if (duration > 0) {
            setTimeout(() => {
              set((s) => ({
                notifications: s.notifications.filter((n) => n.id !== id),
              }));
            }, duration);
          }

          return {
            notifications: [...state.notifications, newNotification],
          };
        }),

      removeNotification: (id) =>
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        })),

      clearNotifications: () => set({ notifications: [] }),

      // Loading state
      isLoading: false,
      setLoading: (loading) => set({ isLoading: loading }),

      // Error state
      error: null,
      setError: (error) => set({ error }),

      // Settings
      locale: 'en',
      setLocale: (locale) => set({ locale }),
    }),
    {
      name: 'articdbm-app-store',
      partialize: (state) => ({
        theme: state.theme,
        sidebarOpen: state.sidebarOpen,
        locale: state.locale,
        user: state.user,
      }),
    }
  )
);

// Convenience hooks for common use cases
export function useUser() {
  return useAppStore((state) => ({
    user: state.user,
    setUser: state.setUser,
    clearUser: state.clearUser,
  }));
}

export function useTheme() {
  return useAppStore((state) => ({
    theme: state.theme,
    setTheme: state.setTheme,
  }));
}

export function useSidebar() {
  return useAppStore((state) => ({
    sidebarOpen: state.sidebarOpen,
    setSidebarOpen: state.setSidebarOpen,
    toggleSidebar: state.toggleSidebar,
  }));
}

export function useNotifications() {
  return useAppStore((state) => ({
    notifications: state.notifications,
    addNotification: state.addNotification,
    removeNotification: state.removeNotification,
    clearNotifications: state.clearNotifications,
  }));
}

export function useLoading() {
  return useAppStore((state) => ({
    isLoading: state.isLoading,
    setLoading: state.setLoading,
  }));
}

export function useAppError() {
  return useAppStore((state) => ({
    error: state.error,
    setError: state.setError,
  }));
}

export function useLocale() {
  return useAppStore((state) => ({
    locale: state.locale,
    setLocale: state.setLocale,
  }));
}
