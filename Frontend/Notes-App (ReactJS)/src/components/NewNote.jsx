import React from "react";

function NewNote({ notesArray, setNotes }) {
  const [newTitle, setNewTitle] = React.useState("");
  const [newBody, setNewBody] = React.useState("");

  function changeTitle(e) {
    setNewTitle(e.target.value);
  }

  function changeBody(e) {
    setNewBody(e.target.value);
  }

  function addNote() {
    const newNote = {
      id: notesArray.length + 1,
      title: newTitle,
      body: newBody,
    };

    setNotes([...notesArray, newNote]);

    setNewTitle("");
    setNewBody("");
  }

  return (
    <div className="newNote">
      <input
        className="input iTitle"
        placeholder="Title"
        value={newTitle}
        onChange={changeTitle}
      />
      <input
        className="input iBody"
        placeholder="Write Description"
        value={newBody}
        onChange={changeBody}
      />
      <button onClick={addNote}>Add</button>
    </div>
  );
}

export default NewNote;
