import { useEffect, useState } from "react";

function App() {
  const [items, setItems] = useState([]);
  const [name, setName] = useState("");
  const [quantity, setQuantity] = useState("");
  const [editingId, setEditingId] = useState(null);

 const API = process.env.REACT_APP_API_URL + "/items";


  const fetchItems = async () => {
    const res = await fetch(API);
    const data = await res.json();
    setItems(data);
  };

  useEffect(() => {
    fetchItems();
  }, []);

  const handleAdd = async () => {
    if (!name || !quantity) return;
    if (editingId) {
      await fetch(`${API}/${editingId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, quantity: parseInt(quantity) })
      });
      setEditingId(null);
    } else {
      await fetch(API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, quantity: parseInt(quantity) })
      });
    }
    setName("");
    setQuantity("");
    fetchItems();
  };

  const handleEdit = (item) => {
    setName(item.name);
    setQuantity(item.quantity);
    setEditingId(item.id);
  };

  const handleDelete = async (id) => {
    await fetch(`${API}/${id}`, { method: "DELETE" });
    fetchItems();
  };

  return (
    <div className="container">
      <h1>Inventory CRUD</h1>

      <div>
        <h2>{editingId ? "Edit Item" : "Add Item"}</h2>
        <input
          placeholder="Item Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          placeholder="Quantity"
          type="number"
          value={quantity}
          onChange={(e) => setQuantity(e.target.value)}
        />
        <button onClick={handleAdd}>{editingId ? "Update" : "Add"}</button>
      </div>

      <div>
        <h2>Items List</h2>
        {items.length === 0 ? <p>No items yet.</p> : (
          <ul>
            {items.map((item) => (
              <li key={item.id}>
                <span>{item.name} - {item.quantity}</span>
                <div>
                  <button onClick={() => handleEdit(item)}>Edit</button>
                  <button onClick={() => handleDelete(item.id)}>Delete</button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default App;
