import { CarsRepositoryInMemory } from '@modules/cars/repositories/in-memory/CarsRepositoryInMemory';

import { ListAvailableCarsUseCase } from './ListAvailableCarsUseCase';

let listAvailableCarsUseCase: ListAvailableCarsUseCase;
let carsRepositoryInMemory: CarsRepositoryInMemory;

describe('List cars', () => {
  beforeEach(() => {
    carsRepositoryInMemory = new CarsRepositoryInMemory();
    listAvailableCarsUseCase = new ListAvailableCarsUseCase(carsRepositoryInMemory);
  });

  it('should be able to list all available cars', async () => {
    const car = await carsRepositoryInMemory.create({
      name: 'Ford Ka',
      description: 'Companheiro de viagem',
      daily_rate: 120.0,
      license_plate: 'RKT-2802',
      fine_amount: 100,
      brand: 'Ford',
      category_id: 'category_id',
    });

    const cars = await listAvailableCarsUseCase.execute({});

    expect(cars).toEqual([car]);
  });

  it('should be able to list all available cars by brand', async () => {
    const car = await carsRepositoryInMemory.create({
      name: 'Ford Ka 2',
      description: 'Companheiro de viagem',
      daily_rate: 120.0,
      license_plate: 'RKT-2802',
      fine_amount: 100,
      brand: 'Ford2',
      category_id: 'category_id',
    });

    const cars = await listAvailableCarsUseCase.execute({
      brand: 'Ford2',
    });

    expect(cars).toEqual([car]);
  });

  it('should be able to list all available cars by name', async () => {
    const car = await carsRepositoryInMemory.create({
      name: 'Ford Ka 3',
      description: 'Companheiro de viagem',
      daily_rate: 120.0,
      license_plate: 'LBD-1234',
      fine_amount: 100,
      brand: 'Ford2',
      category_id: 'category_id',
    });

    const cars = await listAvailableCarsUseCase.execute({
      name: 'Ford3',
    });

    expect(cars).toEqual([car]);
  });

  it('should be able to list all available cars by category', async () => {
    const car = await carsRepositoryInMemory.create({
      name: 'Ford Ka 3',
      description: 'Companheiro de viagem',
      daily_rate: 120.0,
      license_plate: 'LBD-1234',
      fine_amount: 100,
      brand: 'Ford2',
      category_id: '1234',
    });

    const cars = await listAvailableCarsUseCase.execute({
      category_id: '1234',
    });

    expect(cars).toEqual([car]);
  });
});
