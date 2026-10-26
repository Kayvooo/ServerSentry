"use strict";
(() => {
  const ids = ["search", "severity", "status", "rule", "role", "channel"];
  const controls = Object.fromEntries(ids.map(id => [id, document.getElementById(id)]));
  const cards = Array.from(document.querySelectorAll(".finding"));
  // Cache text once; do not repeatedly traverse large evidence blocks while typing.
  const text = new Map(cards.map(card => [card, card.textContent.toLocaleLowerCase()]));
  function filter() {
    const query = controls.search.value.trim().toLocaleLowerCase();
    let count = 0;
    for (const card of cards) {
      const visible = (!query || text.get(card).includes(query)) && ids.slice(1).every(
        id => !controls[id].value || card.dataset[id] === controls[id].value
      );
      card.hidden = !visible;
      if (visible) count++;
    }
    document.getElementById("result-count").textContent = `${count} of ${cards.length} finding groups`;
    document.getElementById("no-results").hidden = count !== 0;
  }
  for (const input of Object.values(controls)) input.addEventListener("input", filter);
  document.getElementById("reset").addEventListener("click", () => {
    for (const input of Object.values(controls)) input.value = "";
    filter();
  });
  const search = document.getElementById("change-search");
  if (search) {
    const changes = Array.from(document.querySelectorAll(".change"));
    const changeText = new Map(changes.map(row => [row, row.textContent.toLocaleLowerCase()]));
    const filterChanges = () => {
      const query = search.value.trim().toLocaleLowerCase();
      let count = 0;
      for (const row of changes) {
        row.hidden = !!query && !changeText.get(row).includes(query);
        if (!row.hidden) count++;
      }
      document.getElementById("change-count").textContent = `${count} of ${changes.length} object changes`;
      document.getElementById("changes-empty").hidden = count !== 0 || changes.length === 0;
    };
    search.addEventListener("input", filterChanges);
    filterChanges();
  }
  filter();
})();
