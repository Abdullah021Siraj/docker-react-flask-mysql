import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import App from './App';

describe('Inventory CRUD App', () => {
  beforeEach(() => {
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve([{ id: 1, name: 'Joggers', quantity: 20 }]),
      })
    );
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  test('renders title and initial items', async () => {
    render(<App />);
    expect(screen.getByText(/Inventory CRUD/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/Joggers - 20/i)).toBeInTheDocument();
    });
  });
});
