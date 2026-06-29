// Small hand-rolled UI primitives (shadcn/ui-style API) themed with the design
// tokens. Kept dependency-light and self-contained.

import {
  forwardRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type TextareaHTMLAttributes,
  type ReactNode,
} from "react";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import { cn } from "../../lib/utils";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const base =
  "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors outline-none focus-visible:ring-2 focus-visible:ring-accent/40 disabled:opacity-50 disabled:cursor-not-allowed select-none";

const variants: Record<Variant, string> = {
  primary:
    "bg-accent text-white hover:opacity-90 shadow-[0_6px_16px_-8px_var(--accent)]",
  secondary:
    "bg-surface text-text-secondary border border-border hover:bg-surface-raised",
  ghost: "text-text-muted hover:text-text hover:bg-surface",
  danger:
    "bg-transparent text-danger border border-[color:var(--danger)]/40 hover:bg-danger-soft",
};

const sizes: Record<Size, string> = {
  sm: "h-8 px-3 text-[13px]",
  md: "h-10 px-4 text-[13.5px]",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "primary", size = "md", loading, className, children, disabled, ...rest }, ref) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={cn(base, variants[variant], sizes[size], className)}
      {...rest}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  ),
);
Button.displayName = "Button";

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string;
  active?: boolean;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ label, active, className, children, ...rest }, ref) => (
    <button
      ref={ref}
      title={label}
      aria-label={label}
      className={cn(
        "inline-flex h-8 w-8 items-center justify-center rounded-md text-text-muted transition-colors hover:text-text hover:bg-surface outline-none focus-visible:ring-2 focus-visible:ring-accent/40",
        active && "text-accent-fg bg-accent-soft",
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  ),
);
IconButton.displayName = "IconButton";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...rest }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-10 w-full rounded-lg border border-border bg-surface px-3 text-[13.5px] text-text placeholder:text-text-dim outline-none transition-shadow focus:border-accent focus:ring-[3px] focus:ring-accent/20",
        className,
      )}
      {...rest}
    />
  ),
);
Input.displayName = "Input";

/** Password field with a built-in show/hide toggle. */
export const PasswordInput = forwardRef<
  HTMLInputElement,
  Omit<InputHTMLAttributes<HTMLInputElement>, "type">
>(({ className, ...rest }, ref) => {
  const [reveal, setReveal] = useState(false);
  return (
    <div className="relative">
      <Input
        ref={ref}
        type={reveal ? "text" : "password"}
        className={cn("pr-10", className)}
        {...rest}
      />
      <div className="absolute right-1 top-1">
        <IconButton
          label={reveal ? "Hide password" : "Show password"}
          type="button"
          tabIndex={-1}
          onClick={() => setReveal((r) => !r)}
        >
          {reveal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </IconButton>
      </div>
    </div>
  );
});
PasswordInput.displayName = "PasswordInput";

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, ...rest }, ref) => (
  <textarea
    ref={ref}
    className={cn(
      "w-full rounded-lg border border-border bg-surface px-3 py-2 text-[13.5px] text-text placeholder:text-text-dim outline-none transition-shadow focus:border-accent focus:ring-[3px] focus:ring-accent/20 resize-none",
      className,
    )}
    {...rest}
  />
));
Textarea.displayName = "Textarea";

export function Badge({
  children,
  onRemove,
  className,
}: {
  children: ReactNode;
  onRemove?: () => void;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-[6px] bg-accent-soft px-2 py-0.5 text-[11px] font-medium text-accent-fg",
        className,
      )}
    >
      {children}
      {onRemove && (
        <button
          type="button"
          onClick={onRemove}
          aria-label="Remove tag"
          className="ml-0.5 text-accent-fg/70 hover:text-accent-fg"
        >
          ×
        </button>
      )}
    </span>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("h-4 w-4 animate-spin text-text-muted", className)} />;
}
