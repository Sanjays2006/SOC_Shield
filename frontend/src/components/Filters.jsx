// Rich alert filters: severity, priority, free-text search, and sort.
export default function Filters({
  setSeverity,
  setPriority,
  setSearch,
  setSort,
}) {
  return (
    <div className="filters-bar">
      <label>
        Severity
        <select onChange={(e) => setSeverity?.(e.target.value)}>
          <option value="">All</option>
          <option>Low</option>
          <option>Medium</option>
          <option>High</option>
          <option>Critical</option>
        </select>
      </label>

      <label>
        Priority
        <select onChange={(e) => setPriority?.(e.target.value)}>
          <option value="">All</option>
          <option>Low</option>
          <option>Medium</option>
          <option>High</option>
          <option>Critical</option>
        </select>
      </label>

      <input
        className="filter-search"
        placeholder="Search IP / signature…"
        onChange={(e) => setSearch?.(e.target.value)}
      />

      <label>
        Sort
        <select onChange={(e) => setSort?.(e.target.value)}>
          <option value="newest">Newest</option>
          <option value="risk">Risk (high→low)</option>
          <option value="score">Score (high→low)</option>
        </select>
      </label>
    </div>
  );
}
